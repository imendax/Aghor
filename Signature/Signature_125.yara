rule signature_125
{
	meta:
		author = "0xlsd"
		sample = "afc8635c6f06775421cefce2187d335c73687b5d18a199db9852c2a73ba55156"
	
	
	strings:
		$string_1 = {
			F2 DD E6
			43
			89 DD
			C6 85 ?? ?? ?? ?? F3
			DD B0 ?? ?? ?? ??
			D7
			71 ??
			CB
			85 F2
			DD C1
			85 F2
			DD C0
			85 F2
			DD DF
			D7
			63 DD
		}
	
	condition:
		any of them
	
}
