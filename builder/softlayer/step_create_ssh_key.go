package softlayer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/mitchellh/multistep"
	"github.com/mitchellh/packer/common/uuid"
	"github.com/mitchellh/packer/packer"
	"golang.org/x/crypto/ssh"
)

type stepCreateSshKey struct {
	keyId          int64
	temporary      bool
	PrivateKeyFile string
}

func (self *stepCreateSshKey) Run(state multistep.StateBag) multistep.StepAction {
	ui := state.Get("ui").(packer.Ui)
	client := state.Get("client").(*SoftlayerClient)
	if self.PrivateKeyFile != "" {
		ui.Say(fmt.Sprintf("Reading private key file (%s)...", self.PrivateKeyFile))

		privateKeyBytes, err := ioutil.ReadFile(self.PrivateKeyFile)
		if err != nil {
			state.Put("error", fmt.Errorf("Error loading configured private key file: %s", err))
			return multistep.ActionHalt
		}

		if self.keyId == 0 {
			key, err := ssh.ParseRawPrivateKey(privateKeyBytes)
			if err != nil {
				return self.error(state, ui, err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return self.error(state, ui, errors.New("the private key is not RSA one"))
			}

			keyId, err := self.uploadSshKey(client, rsaKey)
			if err != nil {
				return self.error(state, ui, err)
			}

			self.keyId = keyId
		} else {
			ui.Say(fmt.Sprintf("Attaching existing sshkey ID to the instance (%d)...", self.keyId))
		}

		state.Put("ssh_key_id", self.keyId)
		state.Put("ssh_private_key", string(privateKeyBytes))

		return multistep.ActionContinue
	}

	ui.Say("Creating temporary ssh key for the instance...")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		return self.error(state, ui, err)
	}

	// ASN.1 DER encoded form
	privDer := x509.MarshalPKCS1PrivateKey(rsaKey)
	privBlk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	keyId, err := self.uploadSshKey(client, rsaKey)
	if err != nil {
		return self.error(state, ui, err)
	}

	self.temporary = true
	self.keyId = keyId

	// Set the private key in the statebag for later
	state.Put("ssh_private_key", string(pem.EncodeToMemory(&privBlk)))
	state.Put("ssh_key_id", keyId)

	ui.Say(fmt.Sprintf("Created SSH key with id '%d'", keyId))

	return multistep.ActionContinue
}

func (self *stepCreateSshKey) Cleanup(state multistep.StateBag) {
	if !self.temporary {
		return
	}

	client := state.Get("client").(*SoftlayerClient)
	ui := state.Get("ui").(packer.Ui)

	ui.Say("Deleting temporary ssh key...")
	err := client.DestroySshKey(self.keyId)

	if err != nil {
		self.error(nil, ui, fmt.Errorf("Error cleaning up ssh key. Please delete the key (%d) manually", self.keyId))
	}
}

func (self *stepCreateSshKey) uploadSshKey(client *SoftlayerClient, rsaKey *rsa.PrivateKey) (keyId int64, err error) {
	pub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return 0, err
	}

	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	// The name of the public key
	label := fmt.Sprintf("packer-%s", uuid.TimeOrderedUUID())
	keyId, err = client.UploadSshKey(label, publicKey)
	if err != nil {
		return 0, err
	}

	return keyId, nil
}

func (self *stepCreateSshKey) error(state multistep.StateBag, ui packer.Ui, err error) multistep.StepAction {
	if ui != nil {
		ui.Error(err.Error())
	}
	if state != nil {
		state.Put("error", err)
	}
	return multistep.ActionHalt
}
