package mux

import (
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rs/zerolog"
)

// Mux implements the ssh agent.Agent interface, combining several Agents into one.
type Mux struct {
	sockets  []string
	upstream []agent.Agent
	logger   zerolog.Logger
}

// List returns the identities known to the agent.
func (m *Mux) List() ([]*agent.Key, error) {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "list")

	k := make([]*agent.Key, 0)

	for _, v := range m.upstream {
		ka, err := v.List()
		if err != nil {
			return nil, err
		}
		k = append(k, ka...)
	}

	return k, nil
}

// Sign attempts to sign data using the connected agents.
func (m *Mux) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "sign")
	l.Str("sha256", ssh.FingerprintSHA256(key))
	l.Str("md5", ssh.FingerprintLegacyMD5(key))

	for n, v := range m.upstream {
		s, err := v.Sign(key, data)

		if err == nil {
			l.Str("upstream", m.sockets[n])
			return s, nil
		}
	}

	err := errors.New("unable to sign")
	l.AnErr("error", err)
	return nil, err
}

// Add adds a private key to the first agent.
func (m *Mux) Add(key agent.AddedKey) error {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "add")

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		l.AnErr("NewSignerFromKey", err)
	}

	l.Str("sha256", ssh.FingerprintSHA256(signer.PublicKey()))
	l.Str("md5", ssh.FingerprintLegacyMD5(signer.PublicKey()))
	l.Str("comment", key.Comment)
	err = m.upstream[0].Add(key)
	l.AnErr("upstream_error", err)
	return err
}

// Remove removes all identities with the given public key from the first agent.
func (m *Mux) Remove(key ssh.PublicKey) error {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "remove")
	l.Str("sha256", ssh.FingerprintSHA256(key))
	l.Str("md5", ssh.FingerprintLegacyMD5(key))

	err := m.upstream[0].Remove(key)
	l.AnErr("upstream_error", err)
	return err
}

// RemoveAll removes all identities from the first agent.
func (m *Mux) RemoveAll() error {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "remove_all")
	err := m.upstream[0].RemoveAll()
	l.AnErr("upstream_error", err)
	return err
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list. (Unsupported.)
func (m *Mux) Lock(passphrase []byte) error {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "lock")
	return errors.New("unsupported")
}

// Unlock undoes the effect of Lock (Unsupported.)
func (m *Mux) Unlock(passphrase []byte) error {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "unlock")
	return errors.New("unsupported")
}

// Signers returns signers for all the known keys.
func (m *Mux) Signers() ([]ssh.Signer, error) {
	l := m.logger.Debug()
	defer l.Send()
	l.Str("method", "signers")

	signers := make([]ssh.Signer, 0)
	for _, v := range m.upstream {
		s, err := v.Signers()
		if err != nil {
			return nil, err
		}
		signers = append(signers, s...)
	}
	return signers, nil
}

type Request struct {
	Sockets []string  // Paths to SSH agent sockets to combine
	Logger  io.Writer // If not nil, logs will be written here
}

func New(req *Request) (*Mux, error) {

	conn := make([]io.ReadWriteCloser, len(req.Sockets))
	upstream := make([]agent.Agent, len(req.Sockets))

	for n, v := range req.Sockets {
		c, err := net.Dial("unix", v)
		if err != nil {
			for i := 0; i < n; i++ {
				conn[i].Close()
			}
			return nil, err
		}
		conn[n] = c
		upstream[n] = agent.NewClient(c)
	}

	writer := io.Discard
	if req.Logger != nil {
		writer = req.Logger
	}

	mux := &Mux{upstream: upstream, logger: zerolog.New(writer)}
	mux.sockets = make([]string, len(req.Sockets))
	copy(mux.sockets, req.Sockets)

	mux.logger.Printf("new mux: %v", mux.sockets)

	return mux, nil
}
