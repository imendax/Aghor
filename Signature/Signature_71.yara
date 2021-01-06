rule signature_71
{
	meta:
		author = "0xlsd"
		sample = "97df6a823be647ba1c813a95ab2e79fdf373d44def9d8b8d34aa9b9b58981c69"
	
	
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
			72 ??
			77 ??
			36 A3 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
