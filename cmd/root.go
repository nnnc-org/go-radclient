/*
Copyright © 2024 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/nnnc-org/go-radclient/src/metrics"
	"github.com/nnnc-org/go-radclient/src/radius"
	"github.com/spf13/cobra"
)

var (
	retries                         int
	retryIntervalStr                string
	retryInterval                   time.Duration
	udpAuthPort                     int
	udpAcctPort                     int
	udpRetries                      int
	udpMTUSize                      int
	udpTimeoutStr                   string
	udpTimeout                      time.Duration
	tcpPort                         int
	tlsTimeoutStr                   string
	tlsTimeout                      time.Duration
	minWriteJitterStr               string
	minWriteJitter                  time.Duration
	maxWriteJitterStr               string
	maxWriteJitter                  time.Duration
	radsecUnsafe                    bool
	tlsAuthenticationKeyLogFilename string
	tlsTunnelKeyLogFilename         string
)

// Attribute variables, each string should be of the format `<label>:<value>[:<type>]`
// The default type for each key-value pair is determined by the key, but it can be
// manually overwritten by appending it to the pair
var (
	sendAttributes    radius.AttributeMap
	receiveAttributes radius.AttributeMap
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "radius-client",
	Short: "RADIUS client that can carry out both UDP and TLS sessions",
	Long: `radius-client is a configurable client that can be
used to carry out both UDP and TLS authentication sessions
for most common authentication protocol.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if jsonOutput {
			if group := topLevelName(cmd); group != authCmd.Name() {
				return fmt.Errorf("--json is not supported for %s yet, only for %s", group, authCmd.Name())
			}
			// The deliberate send jitter defaults to 50ms-1s before every
			// write, which on an EAP exchange of a dozen round trips would be
			// seconds of our own sleep dominating every latency metric. It
			// exists so as not to look like a flood to a busy server, which a
			// once-a-minute single exchange does not. An explicit value is
			// still honored.
			if !cmd.Flags().Changed("min-send-jitter") {
				minWriteJitterStr = "0s"
			}
			if !cmd.Flags().Changed("max-send-jitter") {
				maxWriteJitterStr = "0s"
			}
		}

		rawAttrs, err := cmd.Flags().GetStringArray("attrs-to-send")
		if err != nil {
			return fmt.Errorf("could not get attrs-to-send flag: %w", err)
		}
		sendAttributes, err = parseAttributes(rawAttrs)
		if err != nil {
			return fmt.Errorf("invalid attribute to send: %w", err)
		}

		rawAttrs, err = cmd.Flags().GetStringArray("attrs-to-recv")
		if err != nil {
			return fmt.Errorf("could not get attrs-to-recv flag: %w", err)
		}
		receiveAttributes, err = parseAttributes(rawAttrs)
		if err != nil {
			return fmt.Errorf("invalid attribute to receive: %w", err)
		}
		if retries < 0 {
			return fmt.Errorf("number of retries must be 0 or positive")
		}
		// ReadDatagram uses this as its read-attempt count, so 0 would mean no
		// read is ever attempted and every exchange reports a timeout.
		if udpRetries < 1 {
			return fmt.Errorf("number of UDP retries must be 1 or greater")
		}
		retryInterval, err = time.ParseDuration(retryIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid retry interval: %w", err)
		}
		udpTimeout, err = time.ParseDuration(udpTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid UDP timeout: %w", err)
		}
		tlsTimeout, err = time.ParseDuration(tlsTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid TLS timeout: %w", err)
		}
		minWriteJitter, err = time.ParseDuration(minWriteJitterStr)
		if err != nil {
			return fmt.Errorf("invalid min write jitter: %w", err)
		}
		maxWriteJitter, err = time.ParseDuration(maxWriteJitterStr)
		if err != nil {
			return fmt.Errorf("invalid max write jitter: %w", err)
		}
		if minWriteJitter > maxWriteJitter {
			return fmt.Errorf("max write jitter must be greater than min write jitter")
		}

		return nil
	},
}

func Execute() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) (code int) {
	// Cobra has not parsed anything yet, and a bad flag fails before it does,
	// so --json is detected by hand first.
	jsonOutput = jsonModeRequested(args)
	collector = metrics.New(probeVersion())
	rootCmd.SetArgs(args)

	if !jsonOutput {
		if err := rootCmd.Execute(); err != nil {
			return 1
		}
		return 0
	}

	setupJSONOutput()
	// Without these, every failed probe also prints "Error: ..." and the full
	// usage block to stderr.
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.SetOut(os.Stderr)

	// A probe must always leave parseable output behind, including when it
	// breaks. Note this only covers the main goroutine, which is where every
	// panic site in the probe path lives.
	defer func() {
		if r := recover(); r != nil {
			collector.RecordPanic(r)
			code = emit()
		}
	}()

	err := rootCmd.Execute()
	if err != nil {
		// Ignored by the projection when an attempt was actually made; it only
		// supplies the message for a probe that never reached the network.
		collector.SetConfigError(errors.New(flattenError(err)))
	}
	return emit()
}

// topLevelName returns the name of the command group below the root, e.g.
// "authentication" for "auth udp".
func topLevelName(cmd *cobra.Command) string {
	c := cmd
	for c.Parent() != nil && c.Parent().Parent() != nil {
		c = c.Parent()
	}
	return c.Name()
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&retries, "retries", "r", 0, "Number of retries if the command fails")
	rootCmd.PersistentFlags().StringVarP(&retryIntervalStr, "retry-interval", "I", "0s", "Time between each retry")
	rootCmd.PersistentFlags().IntVar(&udpAuthPort, "udp-auth-port", radius.UDPAuthenticationPort, "RADIUS/UDP authentication port")
	rootCmd.PersistentFlags().IntVar(&udpAcctPort, "udp-acct-port", radius.UDPAccountingPort, "RADIUS/UDP accounting port")
	rootCmd.PersistentFlags().IntVar(&udpRetries, "udp-retries", 2, "RADIUS/UDP packet send retries")
	rootCmd.PersistentFlags().IntVar(&udpMTUSize, "udp-mtu", 1500, "RADIUS/UDP connection MTU size")
	rootCmd.PersistentFlags().StringVar(&udpTimeoutStr, "udp-timeout", "5s", "RADIUS/UDP connection response timeout")
	rootCmd.PersistentFlags().IntVar(&tcpPort, "tcp-port", radius.RadSecTCPPort, "RADIUS/TLS (RadSec) port")
	rootCmd.PersistentFlags().BoolVar(&radsecUnsafe, "radsec-unsafe", false, "RADIUS/TLS (RadSec) skip server authentication")
	rootCmd.PersistentFlags().StringVar(&tlsTimeoutStr, "tls-timeout", "15s", "RADIUS/TLS connection response timeout")
	rootCmd.PersistentFlags().StringVar(&minWriteJitterStr, "min-send-jitter", "50ms", "Min packet send time-in-between jitter")
	rootCmd.PersistentFlags().StringVar(&maxWriteJitterStr, "max-send-jitter", "1s", "Max packet send time-in-between jitter")
	rootCmd.PersistentFlags().StringArray("attrs-to-send", []string{}, `Additional attributes to send. Attributes will be
overwritten if required by protocol executed. Each
entry must be of the format
`+"`[type:value[:value-type] ...]`.")
	rootCmd.PersistentFlags().StringArray("attrs-to-recv", []string{}, `Attributes the client expects to receive. These are
only checked in the last packet of the handshake.
Each entry must be of the format
`+"`[type:value[:value-type] ...]`.")
	rootCmd.PersistentFlags().StringVar(&tlsAuthenticationKeyLogFilename, "tls-auth-key-log-filename", "", "TLS authentication key log file name")
	rootCmd.PersistentFlags().StringVar(&tlsTunnelKeyLogFilename, "tls-tunn-key-log-filename", "", "TLS tunnel key log file")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, `Emit a JSON metrics document on stdout instead of
logging text. Intended for monitoring probes. Defaults
the send jitter to 0s so that latency metrics are not
dominated by deliberate sleeps.`)

	rootCmd.AddCommand(authCmd, acctCmd, statusCmd)
}

func parseAttributes(attrs []string) (radius.AttributeMap, error) {
	// A vendor specific attribute addressed by number carries the vendor ID and
	// the vendor type in its label, every other label is a single word. The
	// value is therefore whatever follows, and may hold colons and equals signs
	// of its own, as a Cisco AVPair does.
	vsa := regexp.QuoteMeta(string(radius.AttributeTypeLabelVendorSpecific))
	r := regexp.MustCompile(`^(?P<Label>` + vsa + `:[0-9]+:[0-9]+|[A-Za-z0-9_-]+):(?P<Value>[\x20-\x7E]+)$`)

	attrMap := make(radius.AttributeMap)

	for _, a := range attrs {
		submatch := r.FindStringSubmatch(a)
		if submatch == nil {
			return nil, fmt.Errorf("invalid attribute entry: %s", a)
		}

		ak, err := radius.AttributeKeyFromString(submatch[r.SubexpIndex("Label")])
		if err != nil {
			return nil, fmt.Errorf("invalid attribute label: %w", err)
		}
		val := submatch[r.SubexpIndex("Value")]
		if slices.Contains(attrMap[ak], val) {
			return nil, fmt.Errorf("duplicate attribute value: %s, %s", a, val)
		}
		attrMap[ak] = append(attrMap[ak], val)
	}

	return attrMap, nil
}
