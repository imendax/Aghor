rule signature_59
{
	meta:
		author = "0xlsd"
		sample = "50d7db66182686ae901b53656512fb7b546a16b6259784c2a5a7a07fedb6672c"
	
	
	strings:
		$string_1 = {
			72 ??
			2F
			31 39
			39 39
			2F
			78 ??
			74 ??
			6C
			22 20
			78 ??
			6C
			3A 6C 61 ??
			67 3D 22 72 75 2D
			72 ??
			22 20
			6C
			61
			6E
		}
	
	condition:
		any of them
	
}
