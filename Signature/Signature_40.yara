rule signature_40
{
	meta:
		author = "0xlsd"
		sample = "2faad0c99f0acb2d27bda308c13069d778471d8d95c03aa4e8c2735f84640fd6"
	
	
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
