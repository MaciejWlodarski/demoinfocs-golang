package common

import "strings"

func isCoachClanTag(clanTag string) bool {
	return clanTag == "[COACH]" ||
		(strings.HasPrefix(clanTag, "[") && strings.HasSuffix(clanTag, " COACH]"))
}

// IsCoach reports whether the player is marked as a coach or has a coach clan tag.
func (p *Player) IsCoach() bool {
	return p != nil && (p.Coaching || isCoachClanTag(p.ClanTag()))
}

// IsCoach reports whether the player is marked as a coach or has a coach clan tag.
// Deprecated: Use Player.IsCoach instead.
func IsCoach(player *Player) bool { return player.IsCoach() }

// IsDuckingOrTransitioning reports the crouch state used for player snapshots.
// When transition properties are unavailable, it falls back to the duck key flag.
func (p *Player) IsDuckingOrTransitioning() bool {
	if p == nil {
		return false
	}
	if p.IsDucking() {
		return true
	}

	pawn := p.PlayerPawnEntity()
	if pawn != nil {
		duckAmount, hasDuckAmount := pawn.PropertyValue("m_pMovementServices.m_flDuckAmount")
		desiresDuck, hasDesiresDuck := pawn.PropertyValue("m_pMovementServices.m_bDesiresDuck")
		if hasDuckAmount && duckAmount.Any != nil && hasDesiresDuck && desiresDuck.Any != nil {
			return p.IsDuckingInProgress() || p.IsUnDuckingInProgress()
		}
	}

	return p.Flags().DuckingKeyPressed()
}

// IsDuckingOrTransitioning reports the crouch state used for player snapshots.
// Deprecated: Use Player.IsDuckingOrTransitioning instead.
func IsDuckingOrTransitioning(player *Player) bool { return player.IsDuckingOrTransitioning() }
