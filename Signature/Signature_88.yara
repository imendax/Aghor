rule signature_88
{
	meta:
		author = "0xlsd"
		sample = "c24d11f906a51c9fede93a33301700123b9e1f8ea3d689cc2be4ded2fa906912"
	
	
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
			7C ??
			93
			27
			38 71 ??
			74 ??
			71 ??
		}
	
	condition:
		any of them
	
}
