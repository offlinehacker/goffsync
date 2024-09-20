package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Mikescher/firefox-sync-client/syncclient"
)

var (
	email    string
	password string
	otp      string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to Firefox Sync",
	Long: `This command allows you to log in to your Firefox Sync account.
It will prompt you for your email and password if not provided as flags.`,
	Run: func(cmd *cobra.Command, args []string) {
		if email == "" || password == "" {
			email, password = promptCredentials()
		}

		client := syncclient.New()
		ctx := context.Background()

		session, verification, err := client.Login(ctx, email, password)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			return
		}

		switch verification {
		case syncclient.VerificationNone:
			fmt.Println("Login successful!")
		case syncclient.VerificationTOTP2FA:
			fmt.Println("Two-factor authentication required.")
			if otp == "" {
				otp = promptOTP()
			}
			err = client.VerifyWithOTP(ctx, session, otp)
			if err != nil {
				fmt.Printf("OTP verification failed: %v\n", err)
				return
			}
			fmt.Println("Two-factor authentication successful!")
		case syncclient.VerificationMail2FA:
			fmt.Println("Email verification required. Please check your email and follow the instructions.")
			return
		default:
			fmt.Printf("Unknown verification method: %v\n", verification)
			return
		}

		err = client.RegisterDevice(ctx, session, "Firefox-Sync-Client (temp)", "cli")
		if err != nil {
			fmt.Printf("Failed to register device: %v\n", err)
			return
		}

		// Fetch keys
		keyA, keyB, err := client.FetchKeys(ctx, session)
		if err != nil {
			fmt.Printf("Failed to fetch keys: %v\n", err)
			return
		}

		keyedSession := session.Extend(keyA, keyB)

		// Acquire OAuth token
		oauthSession, err := client.AcquireOAuthToken(ctx, keyedSession)
		if err != nil {
			fmt.Printf("Failed to acquire OAuth token: %v\n", err)
			return
		}

		// Perform Hawk authentication
		hawkSession, err := client.HawkAuth(ctx, oauthSession)
		if err != nil {
			fmt.Printf("Failed to perform Hawk authentication: %v\n", err)
			return
		}

		// Get crypto keys
		cryptoKeys, err := client.GetCryptoKeys(ctx, hawkSession)
		if err != nil {
			fmt.Printf("Failed to get crypto keys: %v\n", err)
			return
		}

		// Create final session
		keyBundles, err := cryptoKeys.KeyBundles()
		if err != nil {
			fmt.Printf("Failed to create key bundles: %v\n", err)
			return
		}

		finalSession := hawkSession.Extend(keyBundles).Reduce()

		// Save the final session
		err = finalSession.Save("ffsclient_session.json")
		if err != nil {
			fmt.Printf("Failed to save session: %v\n", err)
			return
		}

		fmt.Println("Login process completed successfully!")
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&email, "email", "e", "", "Email for Firefox Sync account")
	loginCmd.Flags().StringVarP(&password, "password", "p", "", "Password for Firefox Sync account")
	loginCmd.Flags().StringVarP(&otp, "otp", "o", "", "One-time password for two-factor authentication")
}

func promptCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	if email == "" {
		fmt.Print("Enter your email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	if password == "" {
		fmt.Print("Enter your password: ")
		passwordBytes, _ := term.ReadPassword(int(syscall.Stdin))
		password = string(passwordBytes)
		fmt.Println() // Add a newline after the password input
	}

	return email, password
}

func promptOTP() string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your OTP: ")
	otp, _ := reader.ReadString('\n')
	return strings.TrimSpace(otp)
}
