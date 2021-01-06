rule signature_22
{
	meta:
		author = "0xlsd"
		sample = "670531da2b4992ca3610835c979bd0f7a688416adbe0b9264e5478d41103a618"
	
	
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
			38 CF
		}
	
	condition:
		any of them
	
}
