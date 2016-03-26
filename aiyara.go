package aiyara

import (
//	"encoding/json"
//	"errors"
	"fmt"
	"bytes"
	"text/template"
	"net"
//	"regexp"
	"os/exec"
	"io/ioutil"
	"os"
	"strconv"
	"time"
	"path/filepath"
	"strings"
//	"flag"

	p "github.com/docker/machine/libmachine/provision"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/machine/libmachine/provision/pkgaction"
	"github.com/docker/machine/libmachine/provision/serviceaction"
//	"github.com/docker/machine/commands/"
//	"github.com/codegangsta/cli"
//	"github.com/docker/machine/commands/mcndirs"
	"github.com/docker/machine/libmachine/auth"
//	host "github.com/docker/machine/libmachine/host"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/drivers"
//	"github.com/docker/machine/libmachine/drivers/rpc"
//	"github.com/docker/machine/libmachine"
	"github.com/docker/machine/libmachine/swarm"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/mcnflag"
//	"github.com/docker/machine/libmachine/mcnerror"
//	"github.com/docker/machine/libmachine/crashreport"
//	"github.com/docker/machine/libmachine/engine"
//	"github.com/docker/machine/libmachine/log"
	utils "github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/state"
)

type Driver struct {
	IPAddress	string
	MachineName string
	StorePath   string

	Host      string
	SSHPort   int
	SSHUser   string
	sshPasswd string
}

type AiyaraProvisioner struct {
	p.SSHCommander
	OsReleaseID       string
	DockerOptionsDir  string
	DaemonOptionsFile string
	Packages          []string
	OsReleaseInfo     *p.OsRelease
	Driver            drivers.Driver
	AuthOptions       auth.Options
	EngineOptions     engine.Options
	SwarmOptions      swarm.Options
}

type Provisioner interface {
	p.Provisioner
	installPublicKey() error
}

const (
	defaultTimeout = 1 * time.Second
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
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

func NewDriver(machineName string, storePath string) drivers.Driver {
	return &Driver{MachineName: machineName, StorePath: storePath}
}

func (d *Driver) Create() error {
	if err := d.createSSHKey(); err != nil {
		return err
	}
	
	aiyaraProvisioner := NewAiyaraProvisioner(d)
	fmt.Println(">>>><<<<<")
	
	if err := aiyaraProvisioner.installPublicKey(); err != nil {
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
	d.IPAddress = "192.168.5.201"
	return d.IPAddress, nil
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
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
	address := net.JoinHostPort(d.IPAddress, strconv.Itoa(d.SSHPort))
	_, err := net.DialTimeout("tcp", address, defaultTimeout)
	var st state.State
	if err != nil {
		st = state.Stopped
	} else {
		st = state.Running
	}
	return st, nil
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

/////////////////////////////////////////////////
/////////////////////////////////////////////////

func NewAiyaraProvisioner(d drivers.Driver) Provisioner {
	return &AiyaraProvisioner{
		Packages: []string{
			"curl",
		},
		Driver: d,
	}
}

func (provisioner *AiyaraProvisioner) Service(name string, action serviceaction.ServiceAction) error {
	command := fmt.Sprintf("sudo service %s %s", name, action.String())

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *AiyaraProvisioner) String() string {
	return "aiyara"
}

func (provisioner *AiyaraProvisioner) GetAuthOptions() auth.Options {
	return provisioner.AuthOptions
}

func (provisioner *AiyaraProvisioner) GetOsReleaseInfo() (*p.OsRelease, error) {
	return provisioner.OsReleaseInfo, nil
}

func (provisioner *AiyaraProvisioner) Package(name string, action pkgaction.PackageAction) error {
	log.Debug("Package doing nothing")
	return nil
}

func (provisioner *AiyaraProvisioner) dockerDaemonResponding() bool {
	log.Debug("checking docker daemon")

	if out, err := provisioner.SSHCommand("sudo docker version"); err != nil {
		log.Warnf("Error getting SSH command to check if the daemon is up: %s", err)
		log.Debugf("'sudo docker version' output:\n%s", out)
		return false
	}

	// The daemon is up if the command worked.  Carry on.
	return true
}

func (provisioner *AiyaraProvisioner) installPublicKey() error {

	if _, err := provisioner.SSHCommand("mkdir ~/.ssh"); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(provisioner.Driver.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}
	
	log.Info("Install public key to server")
	if _, err := provisioner.SSHCommand(fmt.Sprintf("echo \"%s\" | tee -a ~/.ssh/authorized_keys", string(publicKey))); err != nil {
		return err
	}

	return nil
}

func (provisioner *AiyaraProvisioner) installCustomDocker() error {
	// if the old version running, stop it
	provisioner.Service("docker", serviceaction.Stop)

	if _, err := provisioner.SSHCommand("unlink /usr/bin/docker || mkdir -p /opt/docker || unlink /opt/docker/docker"); err != nil {
		return err
	}

	if _, err := provisioner.SSHCommand("wget --no-check-certificate -q -O/opt/docker/docker.tar.xz https://dl.dropboxusercontent.com/u/9350284/docker.tar.xz && (cd /opt/docker && tar -xf docker.tar.xz)"); err != nil {
		return err
	}

	if _, err := provisioner.SSHCommand("chmod +x /opt/docker/docker && ln -s /opt/docker/docker /usr/bin/docker"); err != nil {
		return err
	}

	// install init.d script
	if _, err := provisioner.SSHCommand("wget --no-check-certificate -q -O/etc/init.d/docker https://dl.dropboxusercontent.com/u/9350284/initd-docker.txt && chmod +x /etc/init.d/docker"); err != nil {
		return err
	}
	provisioner.Service("docker", serviceaction.Start)

	return nil
}

func (provisioner *AiyaraProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {

	log.Debug("Entering Provision")

	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	if d0, ok := provisioner.Driver.(interface {
		ClearSSHPasswd()
	}); ok {
		d0.ClearSSHPasswd()
	}

	if err := provisioner.installCustomDocker(); err != nil {
		return err
	}

	if err := utils.WaitFor(provisioner.dockerDaemonResponding); err != nil {
		return err
	}

	return nil
}

func (provisioner *AiyaraProvisioner) Hostname() (string, error) {
	return provisioner.SSHCommand("hostname")
}

func (provisioner *AiyaraProvisioner) SetHostname(hostname string) error {
	if _, err := provisioner.SSHCommand(fmt.Sprintf(
		"sudo hostname %s && echo %q | sudo tee /etc/hostname",
		hostname,
		hostname,
	)); err != nil {
		return err
	}

	// ubuntu/debian use 127.0.1.1 for non "localhost" loopback hostnames: https://www.debian.org/doc/manuals/debian-reference/ch05.en.html#_the_hostname_resolution
	if _, err := provisioner.SSHCommand(fmt.Sprintf(`
		if ! grep -xq .*%s /etc/hosts; then
			if grep -xq 127.0.1.1.* /etc/hosts; then 
				sudo sed -i 's/^127.0.1.1.*/127.0.1.1 %s/g' /etc/hosts; 
			else 
				echo '127.0.1.1 %s' | sudo tee -a /etc/hosts; 
			fi
		fi`,
		hostname,
		hostname,
		hostname,
	)); err != nil {
		return err
	}

	return nil
}

func (provisioner *AiyaraProvisioner) GetDockerOptionsDir() string {
	return "/etc/docker"
}

func (provisioner *AiyaraProvisioner) SSHCommand(args string) (string, error) {
	cmd, err := GetSSHCommandFromDriver(provisioner.Driver, args)
	if err != nil {
		return "",err
	}

	var so bytes.Buffer
	cmd.Stdout = &so

	if err := cmd.Run(); err != nil {
		log.Debug("Error while running command: %s", err)
		return "",err
	}

	return so.String(), nil
}

func (provisioner *AiyaraProvisioner) CompatibleWithHost() bool {
	return provisioner.OsReleaseInfo.ID == provisioner.OsReleaseID
}

func (provisioner *AiyaraProvisioner) SetOsReleaseInfo(info *p.OsRelease) {
	provisioner.OsReleaseInfo = info
}

func (provisioner *AiyaraProvisioner) GenerateDockerOptions(dockerPort int) (*p.DockerOptions, error) {
	var (
		engineCfg bytes.Buffer
	)

	driverNameLabel := fmt.Sprintf("provider=%s", provisioner.Driver.DriverName())
	provisioner.EngineOptions.Labels = append(provisioner.EngineOptions.Labels, driverNameLabel)

	engineConfigTmpl := `
DOCKER_OPTS='
-H tcp://0.0.0.0:{{.DockerPort}}
-H unix:///var/run/docker.sock
--storage-driver {{.EngineOptions.StorageDriver}}
--tlsverify
--tlscacert {{.AuthOptions.CaCertRemotePath}}
--tlscert {{.AuthOptions.ServerCertRemotePath}}
--tlskey {{.AuthOptions.ServerKeyRemotePath}}
{{ range .EngineOptions.Labels }}--label {{.}}
{{ end }}{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}}
{{ end }}{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}}
{{ end }}{{ range .EngineOptions.ArbitraryFlags }}--{{.}}
{{ end }}
'
{{range .EngineOptions.Env}}export \"{{ printf "%q" . }}\"
{{end}}
`
	t, err := template.New("engineConfig").Parse(engineConfigTmpl)
	if err != nil {
		return nil, err
	}

	engineConfigContext := p.EngineConfigContext{
		DockerPort:    dockerPort,
		AuthOptions:   provisioner.AuthOptions,
		EngineOptions: provisioner.EngineOptions,
	}

	t.Execute(&engineCfg, engineConfigContext)

	return &p.DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: provisioner.DaemonOptionsFile,
	}, nil
}

func (provisioner *AiyaraProvisioner) GetDriver() drivers.Driver {
	return provisioner.Driver
}


func GetSSHCommandFromDriver(d drivers.Driver, args ...string)  (*exec.Cmd, error) {
	return getSSHCommandWithSSHPassFromDriver(d, args...)
}

func getSSHCommandWithSSHPassFromDriver(d drivers.Driver, args ...string)  (*exec.Cmd, error) {
	host, err := d.GetSSHHostname()
	if err != nil {
		return nil,err
	}

	port, err := d.GetSSHPort()
	if err != nil {
		return nil,err
	}

	user := d.GetSSHUsername()
	passwd := "1234"
		// if passwd == "" {
		// 	//keyPath := d.GetSSHKeyPath()
		// 	return nil
		// 	//return GetSSHCommand(host, port, user, keyPath, args...), nil
		// }

	return GetSSHCommandWithSSHPass(host, port, user, passwd, args...),nil
}

func GetSSHCommandWithSSHPass(host string, port int, user string, passwd string, args ...string) *exec.Cmd {
	defaultSSHArgs := []string{
		fmt.Sprintf("-p%s", passwd),
		"ssh",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no", // don't bother checking in ~/.ssh/known_hosts
		"-o", "UserKnownHostsFile=/dev/null", // don't write anything to ~/.ssh/known_hosts
		"-o", "ConnectionAttempts=30", // retry 30 times if SSH connection fails
		"-o", "LogLevel=quiet", // suppress "Warning: Permanently added '[localhost]:2022' (ECDSA) to the list of known hosts."
		"-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", user, host),
	}
	
	sshArgs := append(defaultSSHArgs, args...)
	cmd := exec.Command("sshpass", sshArgs...)
	cmd.Stderr = os.Stderr

	if os.Getenv("DEBUG") != "" {
		cmd.Stdout = os.Stdout
	}

	log.Debugf("executing: %v", strings.Join(cmd.Args, " "))

	return cmd
}
