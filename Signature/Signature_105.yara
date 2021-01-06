rule signature_105
{
	meta:
		author = "0xlsd"
		sample = "7d6af8a0c501aad3f2257810ad625be5dbe3f1fef044ec12cc8fcd22cf45a32e"
	
	
	strings:
		$string_1 = {
			5C
			A1 ?? ?? ?? ??
			A2 ?? ?? ?? ??
			2B 8E ?? ?? ?? ??
			CF
			D6
			2F
			E3 ??
			7C ??
			A9 C3 61 6A AE
			45
			63 61 ??
			CA EA 5A
		}
	
	condition:
		any of them
	
}
