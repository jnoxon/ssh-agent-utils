package filter

import (
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrNoMatchingKey = errors.New("no matching key")
)

/*
TODO: Tests
*/

// Filter implements an agent.Agent forwarder that only forwards keys matching selected fingerprints.
// TODO: support multiple fingerprints.
type Filter struct {
	agent        agent.Agent
	fingerprints []string
}

// New returns an agent.Agent that will only sign if the pubkey matches the given fingerprint.
func New(agent agent.Agent, fingerprints []string) agent.Agent {
	return &Filter{agent: agent, fingerprints: fingerprints}
}

// List returns the identities known to the agent.
func (f *Filter) List() ([]*agent.Key, error) {

	keys, err := f.agent.List()
	if err != nil {
		return nil, err
	}

	for _, v := range keys {
		for _, fp := range f.fingerprints {
			if strings.Contains(ssh.FingerprintLegacyMD5(v), fp) ||
				strings.Contains(ssh.FingerprintSHA256(v), fp) {
				return []*agent.Key{v}, nil
			}
		}
	}

	return nil, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (f *Filter) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {

	for _, fp := range f.fingerprints {
		if strings.Contains(ssh.FingerprintLegacyMD5(key), fp) ||
			strings.Contains(ssh.FingerprintSHA256(key), fp) {
			return f.agent.Sign(key, data)
		}
	}

	return nil, ErrNoMatchingKey
}

// Add adds a private key to the agent.
func (f *Filter) Add(key agent.AddedKey) error {
	return f.agent.Add(key)
}

// Remove removes all identities with the given public key.
func (f *Filter) Remove(key ssh.PublicKey) error {
	return f.agent.Remove(key)
}

// RemoveAll removes all identities.
func (f *Filter) RemoveAll() error {
	return f.agent.RemoveAll()
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (f *Filter) Lock(passphrase []byte) error {
	return f.agent.Lock(passphrase)
}

// Unlock undoes the effect of Lock
func (f *Filter) Unlock(passphrase []byte) error {
	return f.agent.Unlock(passphrase)
}

// Signers returns signers for all the known keys.
func (f *Filter) Signers() ([]ssh.Signer, error) {

	signers, err := f.agent.Signers()
	if err != nil {
		return nil, err
	}

	for _, v := range signers {
		for _, fp := range f.fingerprints {
			if strings.Contains(ssh.FingerprintLegacyMD5(v.PublicKey()), fp) ||
				strings.Contains(ssh.FingerprintSHA256(v.PublicKey()), fp) {
				return []ssh.Signer{v}, nil
			}
		}
	}

	return nil, ErrNoMatchingKey
}
