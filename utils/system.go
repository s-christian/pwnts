package utils

import (
	"net"
)

// Get preferred outbound IP address of this machine
func GetHostIP() (hostIP net.IP) {
	netInterfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		CheckErrorExit(Error, err, ERR_GENERIC, "Couldn't obtain host IP address")
		return
	}

	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
			hostIP = networkIp.IP
			return
		}
	}

	return

	/* --- Older method ---
	// Because it uses UDP, the destination doesn't actually have to exist.
	// This will give us the IP address we would normally use to connect out.
	garbageIP := "192.0.2.100"

	conn, err := net.Dial("udp", garbageIP+":80")
	CheckErrorExit(Error, err, ERR_GENERIC, "Couldn't obtain outbound IP address")
	defer Close(conn)

	// We only want the IP, not "IP:port"
	localIP := conn.LocalAddr().(*net.UDPAddr)

	return localIP.IP
	*/
}
