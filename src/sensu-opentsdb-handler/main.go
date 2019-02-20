package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/sensu/sensu-go/types"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var (
	addr               string
	insecureSkipVerify bool
	stdin              *os.File
)

type TSDBMetric struct {
	Metric    string            `json:"metric"`
	Value     float64           `json:"value"`
	Timestamp int64             `json:"timestamp"`
	Tags      map[string]string `json:"tags"`
}

func main() {
	rootCmd := configureRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func configureRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sensu-opentsdb-handler",
		Short: "an opentsdb handler built for use with sensu",
		RunE:  run,
	}

	cmd.Flags().StringVarP(&addr,
		"addr",
		"a",
		os.Getenv("OPENTSDB_ADDR"),
		"the address of the opentsdb server, should be of the form 'http://host:port', defaults to value of OPENTSDB_ADDR env variable")

	cmd.Flags().BoolVarP(&insecureSkipVerify,
		"insecure-skip-verify",
		"i",
		false,
		"if true, the opentsdb client skips https certificate verification")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("invalid argument(s) received")
	}

	if addr == "" {
		return fmt.Errorf("opentsdb addr not set")
	}

	if stdin == nil {
		stdin = os.Stdin
	}

	eventJSON, err := ioutil.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %s", err)
	}

	event := &types.Event{}
	err = json.Unmarshal(eventJSON, event)
	if err != nil {
		return fmt.Errorf("failed to unmarshal stdin data: %s", err)
	}

	if err = event.Validate(); err != nil {
		return fmt.Errorf("failed to validate event: %s", err)
	}

	if !event.HasMetrics() {
		return fmt.Errorf("event does not contain metrics")
	}

	return sendMetrics(event)
}

func sendMetrics(event *types.Event) error {
	now := time.Now().UnixNano() / 1000000

	metrics := make([]*TSDBMetric, 0)

	for _, m := range event.Metrics.Points {
		metric := &TSDBMetric{
			Tags: make(map[string]string, 0),
		}
		metric.Metric = m.Name
		metric.Value = m.Value
		metric.Timestamp = now
		for _, t := range m.Tags {
			metric.Tags[t.Name] = t.Value
		}
		metrics = append(metrics, metric)
	}

	jsonStr, err := json.Marshal(metrics)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", addr+"/api/put", bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}

	client := &http.Client{Transport: tr}
	if _, err = client.Do(req); err != nil {
		return err
	}

	return nil
}
