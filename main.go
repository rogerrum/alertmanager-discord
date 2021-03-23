package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Discord color values
const (
	ColorRed       = 0xd00000
	ColorGreen     = 0x36A64F
	ColorGrey      = 0x95A5A6
	AlertNameLabel = "alertname"
)

type AlertManagerData struct {
	Receiver string             `json:"receiver"`
	Status   string             `json:"status"`
	Alerts   AlertManagerAlerts `json:"alerts"`

	GroupLabels       KV `json:"groupLabels"`
	CommonLabels      KV `json:"commonLabels"`
	CommonAnnotations KV `json:"commonAnnotations"`

	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	Version     string `json:"version"`
}

type AlertManagerAlert struct {
	Status       string    `json:"status"`
	Labels       KV        `json:"labels"`
	Annotations  KV        `json:"annotations"`
	StartsAt     time.Time `json:"startsAt"`
	EndsAt       time.Time `json:"endsAt"`
	GeneratorURL string    `json:"generatorURL"`
	Fingerprint  string    `json:"fingerprint"`
}

// KV is a set of key/value string pairs.
type KV map[string]string

// Pair is a key/value string pair.
type Pair struct {
	Name, Value string
}

// Pairs is a list of key/value string pairs.
type Pairs []Pair

// SortedPairs returns a sorted list of key/value pairs.
func (kv KV) SortedPairs() Pairs {
	var (
		pairs     = make([]Pair, 0, len(kv))
		keys      = make([]string, 0, len(kv))
		sortStart = 0
	)
	for k := range kv {
		if k == AlertNameLabel {
			keys = append([]string{k}, keys...)
			sortStart = 1
		} else {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys[sortStart:])

	for _, k := range keys {
		pairs = append(pairs, Pair{k, kv[k]})
	}
	return pairs
}

// Alerts is a list of Alert objects.
type AlertManagerAlerts []AlertManagerAlert

type DiscordMessage struct {
	Content   string        `json:"content"`
	Username  string        `json:"username"`
	AvatarURL string        `json:"avatar_url"`
	Embeds    DiscordEmbeds `json:"embeds"`
}

type DiscordEmbeds []DiscordEmbed

type DiscordEmbed struct {
	Title       string             `json:"title"`
	Description string             `json:"description"`
	URL         string             `json:"url"`
	Color       int                `json:"color"`
	Fields      DiscordEmbedFields `json:"fields"`
}

type DiscordEmbedFields []DiscordEmbedField

type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

const defaultListenAddress = "127.0.0.1:9094"

var (
	webhookURL    = flag.String("webhook.url", os.Getenv("DISCORD_WEBHOOK"), "Discord WebHook URL.")
	listenAddress = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "Address:Port to listen on.")
	username      = flag.String("username", os.Getenv("DISCORD_USERNAME"), "Overrides the predefined username of the webhook.")
	avatarURL     = flag.String("avatar.url", os.Getenv("DISCORD_AVATAR_URL"), "Overrides the predefined avatar of the webhook.")
)

func checkWebhookURL(webhookURL string) {
	if webhookURL == "" {
		log.Fatalf("Environment variable 'DISCORD_WEBHOOK' or CLI parameter 'webhook.url' not found.")
	}
	_, err := url.Parse(webhookURL)
	if err != nil {
		log.Fatalf("The Discord WebHook URL doesn't seem to be a valid URL.")
	}

	re := regexp.MustCompile(`https://discord(?:app)?.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]+`)
	if ok := re.Match([]byte(webhookURL)); !ok {
		log.Printf("The Discord WebHook URL doesn't seem to be valid.")
	}
}

func sendWebhook(alertManagerData *AlertManagerData) {

	groupedAlerts := make(map[string]AlertManagerAlerts)

	for _, alert := range alertManagerData.Alerts {
		groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)
	}

	for status, alerts := range groupedAlerts {

		discordMessage := DiscordMessage{}

		addOverrideFields(&discordMessage)

		color := findColor(status)

		messageHeader := DiscordEmbed{
			Title:  fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), len(alerts), getAlertName(alertManagerData)),
			URL:    alertManagerData.ExternalURL,
			Color:  color,
			Fields: DiscordEmbedFields{},
		}

		discordMessage.Embeds = DiscordEmbeds{messageHeader}

		for _, alert := range alerts {

			embedAlertMessage := DiscordEmbed{
				Title:  getAlertTitle(&alert),
				Color:  color,
				Fields: DiscordEmbedFields{},
			}

			if alert.Annotations["summary"] != "" {
				embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
					Name:  "*Summary:*",
					Value: alert.Annotations["summary"],
				})
			} else if alert.Annotations["message"] != "" {
				embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
					Name:  "*Message:*",
					Value: alert.Annotations["message"],
				})
			} else if alert.Annotations["description"] != "" {
				embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
					Name:  "*Description:*",
					Value: alert.Annotations["description"],
				})
			}
			embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
				Name:  "*Details:*",
				Value: getFormattedLabels(alert.Labels),
			})
			discordMessage.Embeds = append(discordMessage.Embeds, embedAlertMessage)
		}

		discordMessageBytes, _ := json.Marshal(discordMessage)
		http.Post(*webhookURL, "application/json", bytes.NewReader(discordMessageBytes))
	}
}

func addOverrideFields(discordMessage *DiscordMessage) {
	if *username != "" {
		discordMessage.Username = *username
	}
	if *avatarURL != "" {
		discordMessage.AvatarURL = *avatarURL
	}
}

func getFormattedLabels(labels KV) string {
	var builder strings.Builder
	for _, pair := range labels.SortedPairs() {
		builder.WriteString(fmt.Sprintf(" • *%s:* `%s`\n", pair.Name, pair.Value))
	}
	if builder.Len() == 0 {
		builder.WriteString("-")
	}
	return builder.String()
}

func getAlertTitle(alertManagerAlert *AlertManagerAlert) string {
	var builder strings.Builder
	builder.WriteString("*Alert:*")
	builder.WriteString(alertManagerAlert.Annotations["title"])

	if alertManagerAlert.Labels["severity"] != "" {
		builder.WriteString(" - ")
		builder.WriteString(fmt.Sprintf("`%s`", alertManagerAlert.Labels["severity"]))
	}
	return builder.String()
}

func findColor(status string) int {
	color := ColorGrey
	if status == "firing" {
		color = ColorRed
	} else if status == "resolved" {
		color = ColorGreen
	}
	return color
}

func getAlertName(alertManagerData *AlertManagerData) string {
	if alertManagerData.CommonAnnotations["summary"] != "" {
		return alertManagerData.CommonAnnotations["summary"]
	} else if alertManagerData.CommonAnnotations["message"] != "" {
		return alertManagerData.CommonAnnotations["message"]
	} else if alertManagerData.CommonAnnotations["description"] != "" {
		return alertManagerData.CommonAnnotations["description"]
	} else {
		return alertManagerData.CommonLabels["alertname"]
	}
}

func sendRawPromAlertWarn() {
	badString := `This program is suppose to be fed by alert manager.` + "\n" +
		`It is not a replacement for alert manager, it is a ` + "\n" +
		`webhook target for it. Please read the README.md  ` + "\n" +
		`for guidance on how to configure it for alertmanager` + "\n" +
		`or https://prometheus.io/docs/alerting/latest/configuration/#webhook_config`

	log.Print(`/!\ -- You have misconfigured this program -- /!\`)
	log.Print(`--- --                                      -- ---`)
	log.Print(badString)

	discordMessage := DiscordMessage{
		Content: "",
		Embeds: DiscordEmbeds{
			{
				Title:       "misconfigured program",
				Description: badString,
				Color:       ColorGrey,
				Fields:      DiscordEmbedFields{},
			},
		},
	}

	discordMessageBytes, _ := json.Marshal(discordMessage)
	http.Post(*webhookURL, "application/json", bytes.NewReader(discordMessageBytes))
}

func main() {
	flag.Parse()
	checkWebhookURL(*webhookURL)

	if *listenAddress == "" {
		*listenAddress = defaultListenAddress
	}

	log.Printf("Listening on: %s", *listenAddress)
	http.ListenAndServe(*listenAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - [%s] %s", r.Host, r.Method, r.URL.RawPath)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		alertManagerData := AlertManagerData{}
		err = json.Unmarshal(body, &alertManagerData)
		if err != nil {
			if isRawPromAlert(body) {
				sendRawPromAlertWarn()
				return
			}
			if len(body) > 1024 {
				log.Printf("Failed to unpack inbound alert request - %s...", string(body[:1023]))

			} else {
				log.Printf("Failed to unpack inbound alert request - %s", string(body))
			}
			return
		}
		sendWebhook(&alertManagerData)
	}))
}
