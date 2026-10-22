// Baseline packer-detection rules for gralloch. Generic and safe: they match on
// well-known packer section names / stub markers, not on any specific malware.

rule upx_packed
{
    meta:
        description = "UPX-packed PE (UPX section names / stub marker)"
        category = "packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upxmark = "UPX!"
    condition:
        2 of them
}

rule aspack_packed
{
    meta:
        description = "ASPack-packed PE (section name)"
        category = "packer"
    strings:
        $a = ".aspack"
        $b = ".adata"
    condition:
        any of them
}

rule generic_packer_section
{
    meta:
        description = "Section name of a known runtime packer/protector"
        category = "packer"
    strings:
        $themida = ".themida"
        $vmp0 = ".vmp0"
        $vmp1 = ".vmp1"
        $petite = ".petite"
        $mpress1 = ".MPRESS1"
        $enigma = ".enigma1"
    condition:
        any of them
}
