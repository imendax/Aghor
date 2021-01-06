rule signature_37
{
	meta:
		author = "0xlsd"
		sample = "a74c7bf8d964cf26770ab457b96db6df040051f405a2d736688c1432f6772b1d"
	
	
	strings:
		$string_1 = {
			6F
			72 ??
			2F
			31 39
			39 39
			2F
			78 ??
			74 ??
			6C
			22 3E
			0D 0A 3C 68 65
			61
			64 20 70 ??
			6F
			66 69 6C 65 ?? 22 68
			74 ??
			70 ??
			2F
			2F
		}
	
	condition:
		any of them
	
}
