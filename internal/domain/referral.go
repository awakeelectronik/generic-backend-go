package domain

import "time"

// ReferralCode is the per-user invite code with a max number of redemptions.
type ReferralCode struct {
	UserID       string
	Code         string
	MaxReferrals int
	CreatedAt    time.Time
}

// UserReferral records that a user (UserID) signed up using ReferrerUserID's code.
// One row per signup (UserID is unique).
type UserReferral struct {
	ID             string
	UserID         string
	ReferrerUserID string
	CodeUsed       string
	CreatedAt      time.Time
}
