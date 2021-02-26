package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mitchellh/go-ps"
	winnetstat "github.com/pytimer/win-netstat"
)

var (
	host       *string = flag.String("host", "", "target host or address")
	port       *string = flag.String("port", "0", "target port")
	listenPort *string = flag.String("listen_port", "0", "listen port")
	protocol   *string = flag.String("protocol", "http", "protocol")
	dump       *bool   = flag.Bool("dump", false, "dump data to separate file for each connection")
	identApp   *bool   = flag.Bool("ident_app", false, "Identify application for local connections")
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	if flag.NFlag() < 3 {
		fmt.Printf("usage: tcp-mitm -host <target_host> -port <target_port> -listen_port <local_port> [-protocol <http>] [-dump] [-ident_app]\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	logFile, err := os.OpenFile(strings.TrimSuffix(os.Args[0], filepath.Ext(os.Args[0]))+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetPrefix("> ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds /* | log.Lshortfile*/ | log.Lmsgprefix)

	target := net.JoinHostPort(*host, *port)
	log.Printf("INFO: Start listening on port %s and forwarding data to %s\n", *listenPort, target)
	fmt.Printf("Start listening on port %s and forwarding data to %s\n", *listenPort, target)
	ln, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Printf("ERROR: Unable to start listener, %v\n", err)
		fmt.Printf("Unable to start listener, %v\n", err)
		os.Exit(1)
	}
	connNum := 1
	for {
		if conn, err := ln.Accept(); err == nil {
			from := conn.RemoteAddr().String()
			if *identApp {
				app := identifyApplication(conn.RemoteAddr())
				if app != "" {
					from += " (" + app + ")"
				}
			}
			log.Printf("[%d] TRACE: Accepted connection from %s\n", connNum, from)
			fmt.Printf("[%d] Accepted connection from %s\n", connNum, from)
			go processConnection(conn, connNum, target)
			connNum++
		} else {
			log.Printf("[%d] WARN: Accept failed, %v\n", connNum, err)
			fmt.Printf("[%d] Accept failed, %v\n", connNum, err)
		}
	}
}

func identifyApplication(addr net.Addr) string {
	if addr, ok := addr.(*net.TCPAddr); ok {
		// if !strings.HasPrefix(addr.IP.String(), "127.") && addr.IP.String() != "::1" {
		// 	return ""
		// }
		conns, err := winnetstat.Connections("all")
		if err != nil {
			log.Fatal(err)
		}
		for _, conn := range conns {
			if addr.IP.Equal(net.ParseIP(conn.LocalAddr)) && addr.Port == int(conn.LocalPort) {
				p, err := ps.FindProcess(conn.OwningPid)
				if err != nil {
					log.Fatal(err)
				}
				return p.Executable()
			}
		}
	}
	return ""
}

func processConnection(local net.Conn, connNum int, target string) {
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[%d] WARN: Unable to connect to %s, %v\n", connNum, target, err)
		fmt.Printf("Unable to connect to %s, %v\n", target, err)
		return
	}

	started := time.Now()

	log.Printf("[%d] TRACE: Process connection from %s to %s\n", connNum, local.RemoteAddr().String(), remote.RemoteAddr().String())

	ack := make(chan bool)
	reqLogger := make(chan []byte)
	respLogger := make(chan []byte)

	go dataLogger(reqLogger, respLogger, connNum, local.RemoteAddr().String(), remote.RemoteAddr().String())

	go passThrough(&channel{remote, local, connNum, respLogger, ack})
	go passThrough(&channel{local, remote, connNum, reqLogger, ack})
	<-ack // Make sure that the both copiers gracefully finish.
	<-ack //

	// Stop loggers
	reqLogger <- []byte{}  // Stop "dataLogger"
	respLogger <- []byte{} // Stop "dataLogger"

	finished := time.Now()
	duration := finished.Sub(started)
	log.Printf("[%d] TRACE: Finished connection, duration %s\n", connNum, duration.String())
}

type channel struct {
	from, to   net.Conn
	connNum    int
	dataLogger chan []byte
	ack        chan bool
}

func passThrough(c *channel) {
	b := make([]byte, 8192)
	packetNum := 0
	for {
		n, err := c.from.Read(b)
		if err != nil {
			log.Printf("[%d] TRACE: Disconnected: %v\n", c.connNum, err)
			break
		}
		if n > 0 {
			log.Printf("[%d] TRACE: Received (#%d) %d bytes from %s\n", c.connNum, packetNum, n, c.from.RemoteAddr().String())
			c.dataLogger <- b[:n]
			c.to.Write(b[:n])
			log.Printf("[%d] TRACE: Sent (#%d) to %s\n", c.connNum, packetNum, c.to.RemoteAddr().String())
			packetNum++
		}
	}
	c.from.Close()
	c.to.Close()
	c.ack <- true
}

func dataLogger(req, resp chan []byte, connNum int, localAddress, remoteAddress string) {
	localAddrF := strings.Replace(localAddress, ":", "-", -1)
	remoteAddrF := strings.Replace(remoteAddress, ":", "-", -1)

	var dumpFile *os.File
	if *dump {
		dumpFileName := fmt.Sprintf("dump-%s-%04d-%s-%s.log", time.Now().Format("2006.01.02-15.04.05"), connNum, localAddrF, remoteAddrF)
		var err error
		dumpFile, err = os.OpenFile(dumpFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Unable to open file %s, %v\n", dumpFileName, err)
		}
		defer dumpFile.Close()
	}

	reqData := []byte{}
	respData := []byte{}
	var httpReq *http.Request = nil

out:
	for {
		select {
		case data := <-req:
			if len(data) == 0 {
				break out
			}

			// copy data
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)

			if *dump {
				dumpFile.Write(dataCopy)
				dumpFile.Sync()
			}

			if *protocol == "http" {
				if httpReq != nil {
					log.Printf("[%d] {http} WARN: no response for previous request %s to %s\n", connNum, remoteAddress, localAddress)
					httpReq = nil
				}
				if len(respData) != 0 {
					log.Printf("[%d] {http} WARN: incomplete or incorrect response from %s to %s: %d byte(s)\n", connNum, remoteAddress, localAddress, len(respData))
					respData = []byte{}
				}
				reqData = append(reqData, dataCopy...)
				bufData := append([]byte{}, reqData...)
				buf := bufio.NewReader(bytes.NewBuffer(bufData))
				var err error
				httpReq, err = http.ReadRequest(buf)
				if err == io.EOF {
					log.Printf("[%d] {http} INFO: request EOF from %s to %s: %s\n", connNum, localAddress, remoteAddress, err.Error())
					// waiting for the rest of the request
				} else if err != nil {
					log.Printf("[%d] {http} WARN: incorrect request from %s to %s: %s\n", connNum, localAddress, remoteAddress, err.Error())
				} else {
					log.Printf("[%d] {http} INFO: request from %s to %s: %d byte(s)\n", connNum, localAddress, remoteAddress, len(reqData))
					log.Printf("%+v", httpReq.Header)
					// TODO ...
					reqData = []byte{}
				}
			} else {
				log.Printf("[%d] INFO: request from %s to %s: %d bytes\n", connNum, localAddress, remoteAddress, len(dataCopy))
			}
			// break

		case data := <-resp:
			if len(data) == 0 {
				break out
			}

			// copy data
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)

			if *dump {
				dumpFile.Write(dataCopy)
				dumpFile.Sync()
			}

			if *protocol == "http" {
				if len(reqData) != 0 {
					log.Printf("[%d] {http} WARN: incomplete or incorrect request from %s to %s: %d byte(s)\n", connNum, localAddress, remoteAddress, len(reqData))
					reqData = []byte{}
				}
				if httpReq == nil {
					log.Printf("[%d] {http} WARN: response without request from %s to %s\n", connNum, remoteAddress, localAddress)
				}
				respData = append(respData, dataCopy...)
				bufData := append([]byte{}, respData...)
				buf := bufio.NewReader(bytes.NewBuffer(bufData))
				httpResp, err := http.ReadResponse(buf, httpReq)
				if err == io.EOF {
					log.Printf("[%d] {http} INFO: response EOF from %s to %s: %s\n", connNum, remoteAddress, localAddress, err.Error())
					// waiting for the rest of the response
				} else if err != nil {
					log.Printf("[%d] {http} WARN: incorrect response from %s to %s: %s\n", connNum, remoteAddress, localAddress, err.Error())
				} else {
					log.Printf("[%d] {http} INFO: response from %s to %s: %d byte(s)\n", connNum, remoteAddress, localAddress, len(respData))
					log.Printf("%+v", httpResp.Header)
					// TODO ...
					respData = []byte{}
				}
			} else {
				log.Printf("[%d] INFO: response from %s to %s: %d bytes\n", connNum, remoteAddress, localAddress, len(dataCopy))
			}
			// break

		}

	}

	// if httpReq != nil {
	// 	log.Printf("[%d] {http} WARN: no response for previous request %s to %s\n", connNum, remoteInfo, localInfo)
	// 	httpReq = nil
	// }
	if len(respData) != 0 {
		log.Printf("[%d] {http} WARN: incomplete response from %s to %s: %d byte(s)\n", connNum, remoteAddress, localAddress, len(respData))
		respData = []byte{}
	}
	if len(reqData) != 0 {
		log.Printf("[%d] {http} WARN: incomplete request from %s to %s: %d byte(s)\n", connNum, localAddress, remoteAddress, len(reqData))
		reqData = []byte{}
	}
}
