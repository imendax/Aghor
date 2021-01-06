rule signature_107
{
	meta:
		author = "0xlsd"
		sample = "e8026efaf682a997302fa222349d14cc96b23796e6d13bd2189d38ed909876bf"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			B7 12
			07
			DB F3
			73 ??
			88 F3
			73 ??
		}
	
	condition:
		any of them
	
}
