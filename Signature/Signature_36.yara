rule signature_36
{
	meta:
		author = "0xlsd"
		sample = "1a2326eb9292860c95d1a627f55cb686e39c8a4b9ec8653e53b4cba268532061"
	
	
	strings:
		$string_1 = {
			B1 53
			BE E6 1A 53 81
			7B ??
			53
			BE E6 2F 53 B6
			7B ??
			53
			BE E6 1B 53 D1
			7B ??
			53
			AC
			03 22
			53
			B0 7B
			B1 53
			A5
			7B ??
			53
		}
	
	condition:
		any of them
	
}
