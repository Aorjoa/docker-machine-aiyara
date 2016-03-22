package aiyara

import (
	"fmt"
	"path/filepath"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

// Driver is the driver used when no driver is selected. It is used to
// connect to existing Docker hosts by specifying the URL of the host as
// an option.
type Driver struct {
	*drivers.BaseDriver
	MachineName string
	StorePath   string
	
	Host      string
	SSHPort   int
	SSHUser   string
	sshPasswd string
}

func (d *Driver) GetCreateFlags()  []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:  "aiyara-host-range",
			Usage: "Aiyara Node IP addresses in [from:to] format",
		},
		mcnflag.IntFlag{
			Name:  "aiyara-ssh-port",
			Usage: "Aiyara SSH port",
			Value: 22,
		},
		mcnflag.StringFlag{
			Name:  "aiyara-ssh-user",
			Usage: "Aiyara user name to connect via SSH",
			Value: "root",
		},
		mcnflag.StringFlag{
			Name:  "aiyara-ssh-passwd",
			Usage: "Aiyara host password, must be same for the whole cluster",
			Value: "1234",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	d := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return d
}

func (d *Driver) Create() error {
	if err := d.createSSHKey(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	log.Debug("Creating Key Pair...")
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	return nil
}

func (d *Driver) DriverName() string {
	return "aiyara"
}

func (d *Driver) GetIP() (string, error) {
	return d.Host, nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.Host, nil
}

func (d *Driver) GetSSHPasswd() string {
	return d.sshPasswd
}

func (d *Driver) ClearSSHPasswd() {
	d.sshPasswd = ""
}

func (d *Driver) GetSSHKeyPath() string {
	return filepath.Join(d.StorePath, "id_rsa")
}

func (d *Driver) getSSHPublicKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func (d *Driver) GetSSHPort() (int, error) {
	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

func (d *Driver) GetURL() (string, error) {
	port := 2376
	return fmt.Sprintf("tcp://%s:%d", d.Host, port), nil
}

func (d *Driver) GetState() (state.State, error) {
	return state.None, nil
}


func (d *Driver) Kill() error {
	return fmt.Errorf("hosts without a driver cannot be killed")
}

func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) Remove() error {
	return nil
}

func (d *Driver) Restart() error {
	return fmt.Errorf("hosts without a driver cannot be restarted")
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	// this is generate from host range outside driver
	d.Host = flags.String("aiyara-host-ip")

	d.SSHUser = flags.String("aiyara-ssh-user")
	d.sshPasswd = flags.String("aiyara-ssh-passwd")
	d.SSHPort = flags.Int("aiyara-ssh-port")
	return nil
}

func (d *Driver) Start() error {
	return fmt.Errorf("hosts without a driver cannot be started")
}

func (d *Driver) Stop() error {
	return fmt.Errorf("hosts without a driver cannot be stopped")
}
