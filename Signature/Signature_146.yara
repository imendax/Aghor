rule signature_146
{
	meta:
		author = "0xlsd"
		sample = "6fd453af2f98029bbd9190ece0068a538f064c38d11adb6a143fdd5caa2aeb1d"
	
	
	strings:
		$string_1 = {
			0F 01 0B
			01 05 ?? ?? ?? ??
			00 00
			70 ??
			00 00
			80 05 ?? ?? ?? ?? 00
			00 90 ?? ?? ?? ??
			0A 00
			00 00
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
