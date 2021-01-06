rule signature_27
{
	meta:
		author = "0xlsd"
		sample = "8efafe1ee5cff054083f44c12f5c01ae086797b195f766e53fc9505a2ee8fff6"
	
	
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
