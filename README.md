This repo contains two utilities, `ssh-agent-mux` and `ssh-agent-filter`

This project needs cleanups, documentation, and other improvements.
I'm sharing it in this rough state in case it may be useful to
others. Feedback and pull requests ar welcome!

I use this on macOS to use Secretive along with the built-in agent.

To get started with the mux, try something along these lines:

```
eval `ssh-agent`
ssh-agent-mux -listen-socket $HOME/.ssh_agent/ssh_mux_sock $SSH_AUTH_SOCK $HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

This will listen on the socket `$HOME/.ssh_agent/ssh_mux_sock` and forward all agent requests to all sockets.

Any new keys added will be added only to the first agent.

