package utils

import (
	"net"
)

// Get preferred outbound IP address of this machine
func GetOutboundIP() net.IP {
	// Because it uses UDP, the destination doesn't actually have to exist.
	// This will give us the IP address we would normally use to connect out.
	garbageIP := "192.0.2.100"

	conn, err := net.Dial("udp", garbageIP+":80")
	CheckErrorExit(Error, err, ERR_GENERIC, "Couldn't obtain outbound IP address")
	defer Close(conn)

	// We only want the IP, not "IP:port"
	localIP := conn.LocalAddr().(*net.UDPAddr)

	return localIP.IP
}
