package p9auth

const (
	// The max length of AuthId.
	ANAMELEN = 28

	// The max length of AuthDom.
	DOMLEN = 48

	// The size of a 56-bit DES key.
	DESKEYLEN = 7

	// The size of a challenge.
	CHALLEN = 8

	// The size of a TicketReq.
	TICKREQLEN = (3 * ANAMELEN) + CHALLEN + DOMLEN + 1

	// The size of a Ticket.
	TICKLEN = CHALLEN + (2 * ANAMELEN) + DESKEYLEN + 1
)
