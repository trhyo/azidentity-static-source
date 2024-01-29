// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity-static-source

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/oauth2"
)

const (
	azureClientID            = "AZURE_CLIENT_ID"
	azureTenantID            = "AZURE_TENANT_ID"
	azureFederatedTokentoken = "AZURE_FEDERATED_TOKEN"
)

var (
	errorClientIDNotSpecified = errors.New("no client ID specified. Check pod configuration or set ClientID in the options")
	errorTokenNotSpecified    = errors.New("no token specified. Check pod configuration or set FederatedToken in the options")
	errorTenantIDNotSpecified = errors.New("no tenant ID specified. Check pod configuration or set TenantID in the options")
)

// WorkloadIdentityFederationCredential supports any OIDC-compliant identity provider that supplies a JWT token.
type WorkloadIdentityFederationCredential struct {
	assertion string
	token     oauth2.Token
	cred      *azidentity.ClientAssertionCredential
	expires   time.Time
	mtx       *sync.RWMutex
}

// WorkloadIdentityFederationCredentialOptions contains optional parameters for WorkloadIdentityFederationCredential.
type WorkloadIdentityFederationCredentialOptions struct {
	azcore.ClientOptions

	// AdditionallyAllowedTenants specifies additional tenants for which the credential may acquire tokens.
	// Add the wildcard value "*" to allow the credential to acquire tokens for any tenant in which the
	// application is registered.
	AdditionallyAllowedTenants []string
	// ClientID of the service principal. Defaults to the value of the environment variable AZURE_CLIENT_ID.
	ClientID string
	// DisableInstanceDiscovery should be set true only by applications authenticating in disconnected clouds, or
	// private clouds such as Azure Stack. It determines whether the credential requests Azure AD instance metadata
	// from https://login.microsoft.com before authenticating. Setting this to true will skip this request, making
	// the application responsible for ensuring the configured authority is valid and trustworthy.
	DisableInstanceDiscovery bool
	// TenantID of the service principal. Defaults to the value of the environment variable AZURE_TENANT_ID.
	TenantID string
	// FederatedToken is the federated token to use for authentication. Defaults to the value of the environment variable AZURE_FEDERATED_TOKEN.
	FederatedToken oauth2.Token
}

// NewWorkloadIdentityFederationCredential constructs a WorkloadIdentityFederationCredential. Service principal configuration is read
// from environment variables as set by the Azure workload identity webhook. Set options to override those values.
func NewWorkloadIdentityFederationCredential(options *WorkloadIdentityFederationCredentialOptions) (*WorkloadIdentityFederationCredential, error) {
	if options == nil {
		options = &WorkloadIdentityFederationCredentialOptions{}
	}
	ok := false
	clientID := options.ClientID
	if clientID == "" {
		if clientID, ok = os.LookupEnv(azureClientID); !ok {
			return nil, errorClientIDNotSpecified
		}
	}
	token := options.FederatedToken
	if token.AccessToken == "" {
		if token.AccessToken, ok = os.LookupEnv(azureFederatedTokentoken); !ok || token.AccessToken == "" {
			return nil, errorTokenNotSpecified
		}
	}
	tenantID := options.TenantID
	if tenantID == "" {
		if tenantID, ok = os.LookupEnv(azureTenantID); !ok {
			return nil, errorTenantIDNotSpecified
		}
	}
	w := WorkloadIdentityFederationCredential{token: token, mtx: &sync.RWMutex{}}
	caco := azidentity.ClientAssertionCredentialOptions{
		AdditionallyAllowedTenants: options.AdditionallyAllowedTenants,
		ClientOptions:              options.ClientOptions,
		DisableInstanceDiscovery:   options.DisableInstanceDiscovery,
	}
	cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, w.getAssertion, &caco)
	if err != nil {
		return nil, err
	}

	w.cred = cred
	return &w, nil
}

// GetToken requests an access token from Azure Active Directory. Azure SDK clients call this method automatically.
func (w *WorkloadIdentityFederationCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return w.cred.GetToken(ctx, opts)
}

// getAssertion returns the specified token, which is expected to be a valid JWT token. The token is cached and reused until it expires.
func (w *WorkloadIdentityFederationCredential) getAssertion(context.Context) (string, error) {
	w.mtx.RLock()
	if w.expires.Before(time.Now()) {
		// ensure only one goroutine at a time updates the assertion
		w.mtx.RUnlock()
		w.mtx.Lock()
		defer w.mtx.Unlock()
		// double check because another goroutine may have acquired the write lock first and done the update
		if now := time.Now(); w.expires.Before(now) {
			w.assertion = w.token.AccessToken
			// To be on the safe side, subtract 10 minutes from the token expiry time
			w.expires = w.token.Expiry.Add(-10 * time.Minute)
		}
	} else {
		defer w.mtx.RUnlock()
	}
	return w.assertion, nil
}
