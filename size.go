package p9auth

const (
	// ANAMELEN is the max length of AuthId.
	ANAMELEN = 28

	// DOMLEN is the max length of AuthDom.
	DOMLEN = 48

	// DESKEYLEN is the size of a 56-bit DES key.
	DESKEYLEN = 7

	// CHALLEN is the size of a challenge.
	CHALLEN = 8

	// TICKREQLEN is the size of a TicketReq.
	TICKREQLEN = (3 * ANAMELEN) + CHALLEN + DOMLEN + 1

	// TICKLEN is the size of a Ticket.
	TICKLEN = CHALLEN + (2 * ANAMELEN) + DESKEYLEN + 1
)
