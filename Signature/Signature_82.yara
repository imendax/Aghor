rule signature_82
{
	meta:
		author = "0xlsd"
		sample = "6f6c44bb244555d34b8ed249d44eb577f487158f931f280d60934c80fa360b31"
	
	
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
