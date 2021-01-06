rule signature_25
{
	meta:
		author = "0xlsd"
		sample = "cb0084642c44cb37e1c2a428bf0205d085f7bf2e58350b1ef6dc98868b83be3c"
	
	
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
			F6 E0
		}
	
	condition:
		any of them
	
}
