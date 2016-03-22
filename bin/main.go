package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/aorjoa/docker-machine-aiyara"
)

var Version string

func main() {
	plugin.RegisterDriver(aiyara.NewDriver("", ""))
}
