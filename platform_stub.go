//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

// Linux 平台文件 —— 禁止 TUN 模式，只提供服务器/代理模式。
// 所有 TUN 符号均满足编译，但在运行时 tunMode 永远为 false。

const tunMode = false

func setUnicastIF(fd uintptr, ifaceIndex int, isIPv6 bool) error {
	return fmt.Errorf("IP_UNICAST_IF is unsupported on this platform")
}

func isVirtualInterface(ifaceName string) bool { return false }
func detectPhysIfaceIndexAPI() int            { return -1 }

// getSystemDNSServers — Linux stub（始终返回空列表）
func getSystemDNSServers(iface *net.Interface) []string { return nil }

type TunConfig struct {
	Name                   string
	MTU                    int
	Gateway                []string
	DNS                    []string
	AutoSystemRoutingTable []string
}

var (
	tunName string
	tunMTU  int
)

func init() {
	flag.StringVar(&tunName, "tun-name", "tun0", "TUN 设备名称（Linux 平台禁用）")
	flag.IntVar(&tunMTU, "tun-mtu", 1500, "TUN 设备 MTU（Linux 平台禁用）")
}

func StartTun(*TunConfig) error {
	return fmt.Errorf("TUN: 未实现此平台")
}

func chooseTunIPv4Config() (gatewayCIDR string, dnsIP string) {
	return "10.255.0.1/24", "10.255.0.1"
}

func loadGeoIP()  { log.Printf("[TUN] geoip 数据库跳过（未包含在此构建中）") }
func loadGeoSite() { log.Printf("[TUN] geosite 数据库跳过（未包含在此构建中）") }
