package main

import (
	"bytes"
	//"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/cheynewallace/tabby"
	"github.com/fatih/color"
	whoisparser "github.com/likexian/whois-parser"
	whois "github.com/undiabler/golang-whois"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
)

type Response struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	S       string   `xml:"s,attr"`
	A       string   `xml:"a,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
		} `xml:"Action"`
		ServerVersionInfo struct {
			Text             string `xml:",chardata"`
			H                string `xml:"h,attr"`
			I                string `xml:"i,attr"`
			MajorVersion     string `xml:"MajorVersion"`
			MinorVersion     string `xml:"MinorVersion"`
			MajorBuildNumber string `xml:"MajorBuildNumber"`
			MinorBuildNumber string `xml:"MinorBuildNumber"`
			Version          string `xml:"Version"`
		} `xml:"ServerVersionInfo"`
	} `xml:"Header"`
	Body struct {
		Text                                    string `xml:",chardata"`
		GetFederationInformationResponseMessage struct {
			Text     string `xml:",chardata"`
			Xmlns    string `xml:"xmlns,attr"`
			Response struct {
				Text           string `xml:",chardata"`
				I              string `xml:"i,attr"`
				ErrorCode      string `xml:"ErrorCode"`
				ErrorMessage   string `xml:"ErrorMessage"`
				ApplicationUri string `xml:"ApplicationUri"`
				Domains        struct {
					Text   string   `xml:",chardata"`
					Domain []string `xml:"Domain"`
				} `xml:"Domains"`
				TokenIssuers struct {
					Text        string `xml:",chardata"`
					TokenIssuer struct {
						Text     string `xml:",chardata"`
						Endpoint string `xml:"Endpoint"`
						URI      string `xml:"Uri"`
					} `xml:"TokenIssuer"`
				} `xml:"TokenIssuers"`
			} `xml:"Response"`
		} `xml:"GetFederationInformationResponseMessage"`
	} `xml:"Body"`
}

func main() {

	var asciiart = `
 _      _   ___ _    ____              .      .
| | ___| |_|_ _| |_ / ___| ___         _\/  \/_
| |/ _ \ __|| || __| |  _ / _ \         _\/\/_
| |  __/ |_ | || |_| |_| | (_) |    _\_\_\/\/_/_/_
|_|\___|\__|___|\__|\____|\___/      / /_/\/\_\ \
                                        _/\/\_
Finding the domains you should let go   /\  /\
                                       '      '
p-b--  illegitimateDA  coffeebearsec
Security Risk Advisors
`

	color.Set(color.FgCyan)
	fmt.Println(asciiart)
	color.Unset()

	var domain string

	// Need to build out an actual help dialog and add additional flags
	if len(os.Args) != 2 {
		fmt.Println("Usage: letItGo example_domain.com")
		return
	}
	domain = os.Args[1]

	bare_domains := make(map[string]bool, 0)

	for {
		url := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
		request := []byte(strings.TrimSpace(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header>
	<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
	<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
	<a:ReplyTo>
		<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
	</a:ReplyTo>
</soap:Header>
<soap:Body>
	<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
		<Request>
			<Domain>%s</Domain>
		</Request>
	</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>`, domain)))

		req, err := http.NewRequest("POST", url, bytes.NewReader(request))
		if err != nil {
			fmt.Printf("%#v\n", err)
			//log.Fatal("Error on creating request object. ", err.Error())
			return
		}

		fmt.Println("Pulling tenant domains via Autodiscover")

		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		req.Header.Set("SOAPAction", `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`)
		req.Header.Set("User-Agent", "AutodiscoverClient")

		tr := &http.Transport{
			DisableCompression: true,
		}

		client := &http.Client{Transport: tr}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%#v\n", err)
			fmt.Printf("%#v\n", err.Error())
			return
		}

		var parse_response Response

		if resp.StatusCode != 200 {
			fmt.Println("Error in response. Got code: ", resp.StatusCode)
			if resp.StatusCode == 421 {
				if strings.HasSuffix(domain, "onmicrosoft.com") {
					fmt.Println("Could not find with internal name, abandoning ", domain)
					return
				}
				fmt.Println("No domains found on naive search, retrying with internal naming format ", domain)
				temp_fqdn, err := publicsuffix.EffectiveTLDPlusOne(domain)
				if err != nil {
					fmt.Println(err)
					return
				}
				domain_parts := strings.Split(temp_fqdn, ".")
				if len(domain_parts) > 1 {
					domain = fmt.Sprintf("%s.onmicrosoft.com", domain_parts[len(domain_parts)-2])
					continue
				} else {
					fmt.Println("Could not generate internal domain name from ", domain)
					return
				}
			} else {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Error parsing body...", err)
					return
				}
				fmt.Printf("%s\n", body)
			}
			return
		}
		err = xml.NewDecoder(resp.Body).Decode(&parse_response)
		resp.Body.Close()
		if err != nil {
			fmt.Println(err)
			return
		}

		//fmt.Printf("%#v\n", parse_response.Body.GetFederationInformationResponseMessage.Response.Domains.Domain)

		// TODO
		// uncomment to drop domain list pulled from autodiscover to local file
		// make this some kind of function that can take an input from a flag to output the results from autodiscover
		// file, _ := json.MarshalIndent(parse_response.Body.GetFederationInformationResponseMessage.Response.Domains.Domain, "", " ")
		// _ = ioutil.WriteFile("test2.json", file, 0644)

		for _, domain := range parse_response.Body.GetFederationInformationResponseMessage.Response.Domains.Domain {
			bare_fqdn, err := publicsuffix.EffectiveTLDPlusOne(domain)
			if err != nil {
				fmt.Println(err)
				return
			}
			bare_domains[strings.ToLower(bare_fqdn)] = true

		}
		break
	}

	// Defining the tables that we'll load data into
	tGood := tabby.New()
	tGood.AddHeader("DOMAIN", "EXPIRY", "WHOIS")
	countGood := 0

	tBad := tabby.New()
	tBad.AddHeader("DOMAIN", "ERROR")
	countBad := 0

	tUgly := tabby.New()
	tUgly.AddHeader("DOMAIN", "ERROR")
	countUgly := 0

	fmt.Println("Querying whois for each domain -- this may take some time.")

	for bare_domain := range bare_domains {
		whois_resp, err := whois.GetWhois(bare_domain)
		if err != nil {
			tBad.AddLine(bare_domain, err)
			countBad++
			continue
		}
		result, err := whoisparser.Parse(whois_resp)
		if err != nil {
			tUgly.AddLine(bare_domain, err)
			countUgly++
			continue
		} else {
			tGood.AddLine(bare_domain, result.Domain.ExpirationDate, result.Domain.Status)
			countGood++
		}
	}

	if countUgly != 0 {
		color.Set(color.FgRed)
		fmt.Println("\nThese domains require further investigation. If a domain is not found, it is likely vulnerable.")
		tUgly.Print()
		color.Unset()
	}

	if countBad != 0 {
		color.Set(color.FgYellow)
		fmt.Println("\nThese domains could not be resolved via whois. These domains may require manual investigation.")
		tBad.Print()
		color.Unset()
	}

	if countGood != 0 {
		color.Set(color.FgGreen)
		fmt.Println("\nThese domains are registered and cannot be purchesed until they expire. You should validate that you still own them.")
		tGood.Print()
		color.Unset()
	}

	fmt.Println("\nStats:\nDomains for further investigation: ", countBad+countUgly)
	fmt.Println("Total domains searched: ", countBad+countGood+countUgly)
}
