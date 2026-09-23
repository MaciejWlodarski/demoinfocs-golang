package common

import "strings"

func isCoachClanTag(clanTag string) bool {
	return clanTag == "[COACH]" ||
		(strings.HasPrefix(clanTag, "[") && strings.HasSuffix(clanTag, " COACH]"))
}

// IsCoach reports whether the player is marked as a coach or has a coach clan tag.
func IsCoach(player *Player) bool {
	return player != nil && (player.Coaching || isCoachClanTag(player.ClanTag()))
}

// IsDuckingOrTransitioning reports the crouch state used for player snapshots.
// When transition properties are unavailable, it falls back to the duck key flag.
func IsDuckingOrTransitioning(player *Player) bool {
	if player == nil {
		return false
	}
	if player.IsDucking() {
		return true
	}

	pawn := player.PlayerPawnEntity()
	if pawn != nil {
		duckAmount, hasDuckAmount := pawn.PropertyValue("m_pMovementServices.m_flDuckAmount")
		desiresDuck, hasDesiresDuck := pawn.PropertyValue("m_pMovementServices.m_bDesiresDuck")
		if hasDuckAmount && duckAmount.Any != nil && hasDesiresDuck && desiresDuck.Any != nil {
			return player.IsDuckingInProgress() || player.IsUnDuckingInProgress()
		}
	}

	return player.Flags().DuckingKeyPressed()
}
