package pihole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type LocalDNS interface {
	// List all DNS records.
	List(ctx context.Context) (DNSRecordList, error)

	// Create a DNS record.
	Create(ctx context.Context, domain string, IP string) (*DNSRecord, error)

	// Get first DNS record by its domain.
	Get(ctx context.Context, domain string) (*DNSRecord, error)

	// GetList of all DNS records by its domain
	GetList(ctx context.Context, domain string) ([]*DNSRecord, error)

	// Delete a DNS record by its domain.
	Delete(ctx context.Context, domain string) error
}

var (
	ErrorLocalDNSNotFound = errors.New("local dns record not found")
)

type localDNS struct {
	client *Client
}

type DNSRecord struct {
	IP     string
	Domain string
}

type DNSRecordList []DNSRecord

type dnsRecordListResponse struct {
	Data []dnsRecordResponseObject `json:"data"`
}

type dnsRecordResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	FTLNotRunning bool   `json:"FTLnotrunning"`
}

type dnsRecordResponseObject []string

func (record dnsRecordResponseObject) toDNSRecord() DNSRecord {
	return DNSRecord{
		Domain: record[0],
		IP:     record[1],
	}
}

func (res dnsRecordListResponse) toDNSRecordList() DNSRecordList {
	list := make(DNSRecordList, len(res.Data))

	for i, record := range res.Data {
		list[i] = record.toDNSRecord()
	}

	return list
}

// List returns a list of custom DNS records
func (dns localDNS) List(ctx context.Context) (DNSRecordList, error) {
	req, err := dns.client.Request(ctx, url.Values{
		"customdns": []string{"true"},
		"action":    []string{"get"},
	})
	if err != nil {
		return nil, err
	}

	res, err := dns.client.http.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var resList *dnsRecordListResponse
	if err := json.NewDecoder(res.Body).Decode(&resList); err != nil {
		return nil, fmt.Errorf("failed to parse customDNS list body: %w", err)
	}

	return resList.toDNSRecordList(), nil
}

// Create creates a custom DNS record
func (dns localDNS) Create(ctx context.Context, domain string, IP string) (*DNSRecord, error) {
	req, err := dns.client.Request(ctx, url.Values{
		"customdns": []string{"true"},
		"action":    []string{"add"},
		"ip":        []string{IP},
		"domain":    []string{domain},
	})
	if err != nil {
		return nil, err
	}

	res, err := dns.client.http.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var dnsRes *dnsRecordResponse
	if err := json.NewDecoder(res.Body).Decode(&dnsRes); err != nil {
		return nil, fmt.Errorf("failed to parse customDNS response body: %w", err)
	}

	if !dnsRes.Success {
		return nil, fmt.Errorf("failed to create DNS record %s %s : %s : %w", domain, IP, dnsRes.Message, err)
	}

	results, err := dns.GetList(ctx, domain)
	if err != nil {
		return nil, err
	}

	for _, record := range results {
		if record.Domain == domain && record.IP == IP {
			return record, nil
		}
	}

	return nil, errors.New("record created but not found")
}

// Get returns first custom DNS record by its domain name
func (dns localDNS) Get(ctx context.Context, domain string) (*DNSRecord, error) {
	list, err := dns.GetList(ctx, domain)
	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrorLocalDNSNotFound, domain)
	}

	return list[0], nil
}

// GetList returns all custom DNS records by its domain name
func (dns localDNS) GetList(ctx context.Context, domain string) ([]*DNSRecord, error) {
	list, err := dns.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch custom DNS records: %w", err)
	}

	var results []*DNSRecord
	for _, record := range list {
		if record.Domain == strings.ToLower(domain) {
			results = append(results, &record)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrorLocalDNSNotFound, domain)
	}

	return results, nil
}

// Delete removes a custom DNS record
func (dns localDNS) Delete(ctx context.Context, domain string) error {
	records, err := dns.GetList(ctx, domain)
	if err != nil {
		if errors.Is(err, ErrorLocalDNSNotFound) {
			return nil
		}
		return fmt.Errorf("failed looking up custom DNS record %s for deletion: %w", domain, err)
	}

	for _, record := range records {
		if err := func() error {
			req, err := dns.client.Request(ctx, url.Values{
				"customdns": []string{"true"},
				"action":    []string{"delete"},
				"domain":    []string{record.Domain},
				"ip":        []string{record.IP},
			})
			if err != nil {
				return err
			}

			res, err := dns.client.http.Do(req)
			if err != nil {
				return err
			}

			defer res.Body.Close()

			var delRes dnsRecordResponse
			if err := json.NewDecoder(res.Body).Decode(&delRes); err != nil {
				return fmt.Errorf("failed to parse custom DNS deletion response body: %w", err)
			}

			if !delRes.Success {
				return fmt.Errorf("failed to delete custom DNS record %s: %s", domain, delRes.Message)
			}
			return nil
		}(); err != nil {
			return err
		}
	}

	return nil
}
