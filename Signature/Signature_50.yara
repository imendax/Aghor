rule signature_50
{
	meta:
		author = "0xlsd"
		sample = "541d7dfde215b1bdabef0bc481f1950a027275b4df611b8789405573f6d52b0e"
	
	
	strings:
		$string_1 = {
			D2 6B ??
			58
			D3 6B ??
			58
			D2 6B ??
			58
			D2 6B ??
			58
			D2 6B ??
			0A 51 ??
			D9 58 ??
			6B C6 0A
			46
			6B D9 58
			D2 6B ??
			0A 43 ??
		}
	
	condition:
		any of them
	
}
