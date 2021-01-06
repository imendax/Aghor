rule signature_58
{
	meta:
		author = "0xlsd"
		sample = "0aceb306c7b2520439c043962d30d0294606688704119fcc138d58c5999cce79"
	
	
	strings:
		$string_1 = {
			CA 31 ED
			14 D6
			31 3C 37
			CA 31 37
			37
			CB
			31 7A ??
			CA 31 CD
			14 D3
			31 3E
			37
			CA 31 A0
			14 8F
			31 36
			37
			CA 31 ED
			14 D7
		}
	
	condition:
		any of them
	
}
