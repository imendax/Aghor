rule signature_24
{
	meta:
		author = "0xlsd"
		sample = "cc671ba549994f7c35aca4552ecb71ae072a226c85db185f4ffb318ddb457d4c"
	
	
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
			50
			45
		}
	
	condition:
		any of them
	
}
