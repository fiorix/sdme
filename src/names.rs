use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Result};

const VOWELS: &[u8] = b"aeiou";

/// Variations of Tupi-Guarani words and names used for container name generation.
const WORDLIST: &[&str] = &[
    "tinguituguassu",
    "guarueguaguara",
    "juruiuimatuba",
    "tucarabaranga",
    "pirauemaranga",
    "pacaucajupara",
    "acajuucaguara",
    "curiguaracaba",
    "umuaguarapura",
    "sapiumadidaba",
    "indakuibicaba",
    "tucarucuguata",
    "umuabanapira",
    "janditibaobi",
    "juruatomoiru",
    "paraoraranga",
    "jabaumaromba",
    "botoibiquara",
    "sapipoibaipa",
    "mbiraebupore",
    "jataguataaca",
    "indaomiriari",
    "mucuquaranda",
    "votupumbioca",
    "caraiuubagui",
    "botoitubaira",
    "jabagoacuque",
    "acajuonhandu",
    "mbirarabaibi",
    "iporainhaaru",
    "jatangutinga",
    "juruetutaemu",
    "iporaquaanha",
    "birakingunda",
    "jataicaruacu",
    "umuaicakonha",
    "jurutibapuru",
    "nitecabadaba",
    "corookuvunda",
    "tabairudimba",
    "ndaraanhaemu",
    "angaringaqua",
    "jabaangarema",
    "pacanearaaca",
    "tingutibaiti",
    "indabanaidi",
    "carannguatu",
    "mboamamaeca",
    "umuajaviaru",
    "mogikeuiavu",
    "jatavoguara",
    "sapiobameja",
    "iporaatumbu",
    "nhanjaituji",
    "macavaarisi",
    "puricabaeia",
    "tupiuimuura",
    "anhacabaaca",
    "guaraguaque",
    "iporanhaacu",
    "catuitutiba",
    "piraugianga",
    "tiriutupore",
    "capoarapaja",
    "guarparaoca",
    "jacutuabaka",
    "maranhopore",
    "tupiruumaui",
    "botoirasare",
    "jatatingacu",
    "pirauracusu",
    "maranequara",
    "mandiibooba",
    "camuiparaba",
    "jatatibaaba",
    "macaemarema",
    "mandiimaita",
    "botutubandu",
    "piraubaanga",
    "tingugocema",
    "paraipatasa",
    "sapidabaama",
    "indauaroori",
    "umuaacaieko",
    "tapuonhaibo",
    "piruipemana",
    "guarameieco",
    "curinhetaba",
    "umuatujuacu",
    "capoquarami",
    "macanemagui",
    "miriguimuco",
    "iporakepaba",
    "pacairuinga",
    "juruauraati",
    "tapimutinga",
    "juruacemaki",
    "caranataacu",
    "maraemanavi",
    "tabanuconda",
    "guaiingaura",
    "murucabamba",
    "tucabokanda",
    "capivukuiti",
    "acannuoraua",
    "botuumacara",
    "indajiringa",
    "nitemitinga",
    "mandiboiaga",
    "guaratibaua",
    "caranjeeacu",
    "guarateruca",
    "maracabaiba",
    "tamaassuacu",
    "jabarangamo",
    "caranmubite",
    "miritiquara",
    "tupicuabaki",
    "mirijutuba",
    "caraemaetu",
    "capouarumi",
    "ubagonhivo",
    "puritibadi",
    "sapinocuru",
    "niteiboeia",
    "botutubaca",
    "catuibiitu",
    "anhandaiae",
    "sapiemaiee",
    "niteecumbu",
    "jabaeianhe",
    "iporairiji",
    "curiicaiie",
    "ubaurarema",
    "jataemaque",
    "curiguassu",
    "itaocapira",
    "ibicaranga",
    "jacutibaco",
    "nhankoiumi",
    "macaipeoba",
    "miritaunga",
    "ibiguguara",
    "ipaneubaje",
    "capooimame",
    "ubabeatuua",
    "tinguguaki",
    "nitenuassu",
    "acajundiiu",
    "jagudupora",
    "acajuvonga",
    "guaiaeiati",
    "juruguinga",
    "pirapigovi",
    "turiecuoba",
    "sapiassusa",
    "ndaravaoke",
    "umuaacaaga",
    "caramanape",
    "araciubaia",
    "nhanacaira",
    "apiravuibi",
    "caporetume",
    "tapumanaci",
    "caratabaua",
    "capopuruni",
    "niteingava",
    "pindaetuma",
    "paraatauia",
    "guaracubea",
    "purijaueji",
    "jacudituba",
    "capombuuba",
    "turiungapu",
    "sapietunga",
    "carabaracu",
    "tapiimambu",
    "jucaecaema",
    "itaonhanoe",
    "jabamutuba",
    "capobapora",
    "jacuuraica",
    "tucaangaga",
    "jeriocauba",
    "guartipore",
    "mboaemaama",
    "puringaibo",
    "murueiaecu",
    "indapurucu",
    "juruameeca",
    "iporajaipa",
    "pirukidaba",
    "jerinhouma",
    "piratabavo",
    "aramoabaro",
    "tabacemape",
    "niteiboqua",
    "mandiamako",
    "juruajaara",
    "capoobaiti",
];

fn random_usize() -> Result<usize> {
    let mut buf = [0u8; 8];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(usize::from_ne_bytes(buf))
}

fn shuffle<T>(words: &mut [T]) -> Result<()> {
    for i in (1..words.len()).rev() {
        let j = random_usize()? % (i + 1);
        words.swap(i, j);
    }
    Ok(())
}

fn is_name_taken(datadir: &Path, name: &str, machines: &[String]) -> bool {
    if datadir.join("state").join(name).exists() {
        return true;
    }
    if Path::new("/var/lib/machines").join(name).exists() {
        return true;
    }
    machines.iter().any(|m| m == name)
}

fn mutate_vowels(word: &str) -> Result<String> {
    let bytes = word.as_bytes();
    let vowel_positions: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|(_, &b)| VOWELS.contains(&b))
        .map(|(i, _)| i)
        .collect();

    if vowel_positions.is_empty() {
        bail!("word has no vowels to mutate");
    }

    let mut result = bytes.to_vec();

    // Pick how many vowels to change: 1 or 2.
    let count = if vowel_positions.len() == 1 {
        1
    } else {
        (random_usize()? % 2) + 1
    };

    // Pick which positions to change.
    let mut positions = vowel_positions.clone();
    // Fisher-Yates partial shuffle to pick `count` positions.
    for i in 0..count.min(positions.len()) {
        let j = i + (random_usize()? % (positions.len() - i));
        positions.swap(i, j);
    }

    for &pos in &positions[..count.min(positions.len())] {
        let current = result[pos];
        // Pick a different vowel.
        let mut new_vowel = VOWELS[random_usize()? % VOWELS.len()];
        while new_vowel == current {
            new_vowel = VOWELS[random_usize()? % VOWELS.len()];
        }
        result[pos] = new_vowel;
    }

    Ok(String::from_utf8(result).expect("vowel mutation produced invalid utf-8"))
}

pub fn generate_name(datadir: &Path) -> Result<String> {
    let mut words: Vec<&str> = WORDLIST.to_vec();
    shuffle(&mut words)?;

    let machines = crate::systemd::list_machines();

    // Try each base word.
    for word in &words {
        if !is_name_taken(datadir, word, &machines) {
            return Ok(word.to_string());
        }
    }

    // All base words taken; try vowel mutations.
    for _ in 0..200 {
        let base = words[random_usize()? % words.len()];
        let mutated = mutate_vowels(base)?;
        if crate::validate_name(&mutated).is_ok() && !is_name_taken(datadir, &mutated, &machines) {
            return Ok(mutated);
        }
    }

    bail!("failed to generate a unique container name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_wordlist() {
        assert_eq!(WORDLIST.len(), 200, "expected 200 words in wordlist");
        let mut seen = HashSet::new();
        for word in WORDLIST {
            assert_eq!(*word, word.to_lowercase(), "word not lowercase: {word}");
            assert!(
                crate::validate_name(word).is_ok(),
                "word fails validate_name: {word}"
            );
            assert!(seen.insert(*word), "duplicate word: {word}");
        }
    }

    #[test]
    fn test_generate_name_basic() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-names-basic-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let name = generate_name(&tmp).unwrap();
        assert!(crate::validate_name(&name).is_ok());
        assert!(
            WORDLIST.contains(&name.as_str()),
            "name should be from wordlist"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_generate_name_avoids_existing() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-names-avoid-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        let state_dir = tmp.join("state");
        fs::create_dir_all(&state_dir).unwrap();

        // Block the first 5 words.
        for word in &WORDLIST[..5] {
            fs::write(state_dir.join(word), "NAME=x\n").unwrap();
        }

        let name = generate_name(&tmp).unwrap();
        assert!(crate::validate_name(&name).is_ok());
        for word in &WORDLIST[..5] {
            assert_ne!(&name, word, "should not return a blocked name");
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_mutate_vowels() {
        let word = "tinguituguassu";
        for _ in 0..10 {
            let mutated = mutate_vowels(word).unwrap();
            assert_ne!(mutated, word, "mutation should differ from input");
            assert_eq!(mutated.len(), word.len(), "length should be preserved");
            assert!(crate::validate_name(&mutated).is_ok());
            // Consonants should be unchanged.
            for (i, (a, b)) in word.bytes().zip(mutated.bytes()).enumerate() {
                if !VOWELS.contains(&a) {
                    assert_eq!(a, b, "consonant at position {i} changed");
                }
            }
        }
    }

    #[test]
    fn test_generate_name_falls_back_to_mutation() {
        let tmp = std::env::temp_dir().join(format!(
            "sdme-test-names-mutation-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        let state_dir = tmp.join("state");
        fs::create_dir_all(&state_dir).unwrap();

        // Block all 200 base words.
        for word in WORDLIST {
            fs::write(state_dir.join(word), "NAME=x\n").unwrap();
        }

        let name = generate_name(&tmp).unwrap();
        assert!(crate::validate_name(&name).is_ok());
        assert!(
            !WORDLIST.contains(&name.as_str()),
            "name should be a mutation, not a base word"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
