package redact

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// firstNames is an offline list of common given names from many languages.
// Names that are also everyday English words or product names (Will, May,
// Mark, Grace, Bill, Ruby, Julia, Jordan, Paris...) are left out on purpose:
// they are still caught after a title or a "name:" key.
const firstNames = `
Aaron Abdallah Abdel Abdelaziz Abdelkader Abdellah Abdelhak Abdelilah Abderrahim Abderrahmane Abdou Abdoulaye Abdul Abdullah Abel Abigail Achraf Adam Adel Adele Adil Adnane Adrian Adriana Adrien Agathe Agnes Ahmad Ahmed Aicha Aisha Aissa Ajay Akira Alain Alan Albert Alberto Alejandra Alejandro Aleksandr Alessandra Alessandro Alex Alexander Alexandra Alexandre Alexandru Alexis Alfonso Alfred Alhassane Ali Alice Alicia Alina Alison Allison Amal Amanda Amandine Amani Amar Amelia Amelie Amina Amine Amir Amira Amit Amy Ana Anais Anas Anastasia Andre Andrea Andreas Andrei Andres Andrew Andy Angela Angelica Angelina Angelo Anil Anita Anjali Ann Anna Annabelle Anne Annette Annie Anthony Antoine Anton Antonio Anwar Arjun Arnaud Arthur Arun Asma Assia Aubrey Audrey Aurelie Austin Ayman Ayoub Aziz Aziza
Badr Bakary Barbara Bastien Beatrice Benjamin Benoit Bernard Bertrand Bilal Bob Bouchra Brahim Brandon Brenda Brian Brigitte Bruno Bryan
Camille Carla Carlos Carmen Caroline Catherine Cecile Cedric Celine Charles Charlotte Chen Cheng Chiara Chloe Chris Christian Christina Christine Christophe Christopher Claire Clara Claude Claudia Clement Colin Corentin Cristina Cyril
Damien Daniel Daniela Danielle Daniele Danny David Debora Deborah Denis Dennis Derek Diana Diane Didier Diego Dimitri Dmitry Dominique Donald Douglas Driss Dylan
Edouard Eduardo Edward Elena Elias Elie Elisa Elisabeth Elise Elizabeth Ella Ellen Elodie Emilie Emily Emma Emmanuel Emmanuelle Enrique Enzo Eric Erik Erika Ethan Etienne Eugene Eva Evan Evelyne
Fabien Fabienne Fabio Fabrice Fadoua Fahd Faisal Farah Farid Fatiha Fatima Fatma Fatou Federico Felipe Felix Fernando Florence Florent Florian Francesca Francesco Francisco Francois Francoise Frederic Frederick
Gabriel Gabriela Gabrielle Gael Gary Gaston Genevieve George Georges Gerald Gerard Ghita Gilbert Gilles Giorgio Giovanni Giulia Giuseppe Gregory Guillaume Gustavo
Habib Hafsa Hajar Hakim Hamid Hamza Hana Hanane Hannah Hans Harry Hassan Hassane Hatim Hayat Hector Helen Helena Helene Henri Henry Herve Hicham Hiba Hind Hiroshi Hoang Houda Hugo Hussein
Ian Ibrahim Ibrahima Idriss Igor Ilham Ilias Ilyas Ilyass Imad Iman Imane Ines Ingrid Irina Isaac Isabel Isabella Isabelle Ismael Ismail Ivan
Jacqueline Jacques Jaime James Jamal Jamila Jan Jane Janet Janice Jason Javier Jawad Jean Jeanne Jeff Jeffrey Jennifer Jeremy Jerome Jessica Joanna Joao Joel Johan Johann Johanna John Johnny Jonathan Jorge Jose Josef Joseph Josephine Joshua Juan Judith Julie Julien Juliette Justin
Kamal Karim Karima Karen Karl Kate Katherine Kathleen Katia Kawtar Keith Kelly Kenji Kenneth Kevin Khadija Khalid Khaled Kim Kimberly Klaus Kofi Kumar Kyle
Lahcen Laila Lamia Larbi Larry Latifa Laura Laure Laurence Laurent Lea Leila Lena Leo Leon Leonardo Lina Linda Lisa Lorenzo Louis Louise Luc Luca Lucas Lucia Lucie Luis Luisa Lukas
Madeleine Mahmoud Malak Malika Manon Manuel Manuela Marc Marcel Marco Marcus Margaux Margot Maria Mariam Marie Marina Mario Marion Mariya Marouane Martin Martina Mary Maryam Mathieu Mathilde Matteo Matthew Matthias Maurice Maxime Mehdi Melanie Meriem Meryem Michael Michel Michele Michelle Miguel Mina Mohamed Mohammed Mohamad Mohammad Mohsine Mona Monica Monique Mostafa Mouad Mounir Mourad Moussa Mustapha Mustafa Myriam
Nabil Nadia Nadine Naima Najat Najib Naoufal Narjis Natalia Natalie Nathalie Nathan Nicolas Nicole Nikita Nikolai Nina Noah Noemie Nora Nordine Nour Noura Nouha
Olga Olivia Olivier Omar Oscar Othmane Oumaima Ousmane Oussama
Pablo Paolo Pascal Pascale Patricia Patrick Paul Paula Paulo Pedro Peter Philippe Pierre Pietro Priya
Rachel Rachid Rahul Rajesh Rania Raphael Rashid Rebecca Redouane Reda Remi Renaud Richard Robert Roberto Rodrigo Romain Rachida Rosa Rosalie Ryan
Saad Sabrina Sacha Safae Safia Said Saida Salah Salim Salma Samantha Sami Samia Samir Samira Samuel Sana Sandra Sandrine Sanjay Sara Sarah Sebastian Sebastien Sergei Sergio Simon Simone Siham Sofia Sophia Sophie Soufiane Soukaina Stefan Stefano Stephane Stephanie Stephen Steve Steven Susan Sylvain Sylvie
Tarik Tariq Thibault Thierry Thomas Timothy Tobias Tomas Toufik Tristan
Valentin Valerie Vanessa Veronique Victoria Vincent Virginie Vladimir
Walid Wassim Wendy William Wissal Wolfgang
Xavier Yann Yannick Yasmina Yasmine Yassin Yassine Yasser Yohan Youness Younes Youssef Yousra Yves Yvonne
Zahra Zainab Zakaria Zineb Zoe Zoubir
`

// accentFold maps accented letters so "Hélène" matches "Helene".
var accentFold = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ä", "a", "ã", "a", "å", "a",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"í", "i", "ì", "i", "î", "i", "ï", "i",
	"ó", "o", "ò", "o", "ô", "o", "ö", "o", "õ", "o",
	"ú", "u", "ù", "u", "û", "u", "ü", "u", "ç", "c", "ñ", "n",
	"É", "E", "È", "E", "Ê", "E", "À", "A", "Â", "A", "Î", "I", "Ô", "O", "Ç", "C",
)

var firstNameSet = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(firstNames) {
		m[strings.ToLower(n)] = true
	}
	return m
}()

// A capitalised name word: "Smith", "O'Neil", "Saint-Exupéry", "DUPONT".
const nameWord = `\p{Lu}(?:[\p{Ll}'’]+(?:-\p{Lu}?[\p{Ll}'’]+)*|\p{Lu}{1,}(?:-\p{Lu}+)*)`
const nameParticle = `(?:de|da|del|della|di|van|von|der|den|le|la|du|des|ben|bin|bint|ibn|el|al|ait|ou|y)`

var (
	capWordRe   = regexp.MustCompile(`\p{Lu}[\p{L}'’-]*`)
	surnameRe   = regexp.MustCompile(`^(?:[ \t]+(?:` + nameParticle + `[ \t]+)?` + nameWord + `){1,3}`)
	titleNameRe = regexp.MustCompile(`\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Mme|Mlle|Mr|Sr|Sra|Srta|Herr|Frau|Sir|Dame|Madam|Madame|Monsieur|Mademoiselle|Docteur|Doctor|Professor|Sidi|Lalla|Hajj|Haj)\.?[ \t]+(` + nameWord + `(?:[ \t]+(?:` + nameParticle + `[ \t]+)?` + nameWord + `){0,3})`)
	keyNameRe   = regexp.MustCompile(`(?i:\b(?:full[ _-]?name|first[ _-]?name|last[ _-]?name|surname|given[ _-]?name|family[ _-]?name|display[ _-]?name|real[ _-]?name|customer|client|employee|patient|contact|author|owner|assignee|reporter|requester|recipient|sender|signed[ _-]by|approved[ _-]by|attn|nom|pr[ée]nom|name))["']?[ \t]*[:=][ \t]*["']?(` + nameWord + `(?:[ \t]+(?:` + nameParticle + `[ \t]+)?` + nameWord + `){0,3})`)
)

// nameNotWords are capitalised words that start a sentence or a log field
// and must not be taken as a surname.
var nameNotWords = map[string]bool{
	"the": true, "and": true, "or": true, "but": true, "from": true, "to": true, "in": true, "on": true,
	"at": true, "for": true, "with": true, "is": true, "was": true, "has": true, "had": true,
	"error": true, "warn": true, "warning": true, "info": true, "debug": true, "fatal": true,
	"get": true, "post": true, "put": true, "delete": true, "patch": true, "head": true, "ok": true,
	"true": true, "false": true, "null": true, "none": true, "id": true, "api": true, "http": true, "https": true,
	"user": true, "admin": true, "server": true, "default": true, "test": true,
	"mr": true, "mrs": true, "ms": true, "miss": true, "mx": true, "dr": true, "prof": true, "mme": true,
	"mlle": true, "sir": true, "madam": true, "madame": true, "monsieur": true, "herr": true, "frau": true,
}

func trimNameWords(v string) string {
	ws := strings.Fields(v)
	for len(ws) > 1 && nameNotWords[strings.ToLower(ws[len(ws)-1])] {
		ws = ws[:len(ws)-1]
	}
	if len(ws) > 0 && nameNotWords[strings.ToLower(ws[0])] {
		return ""
	}
	return strings.Join(ws, " ")
}

func isLetterAt(text string, i int, before bool) bool {
	var r rune
	if before {
		if i <= 0 {
			return false
		}
		r, _ = utf8.DecodeLastRuneInString(text[:i])
	} else {
		if i >= len(text) {
			return false
		}
		r, _ = utf8.DecodeRuneInString(text[i:])
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// findNames finds people's names: a known first name (with the surname that
// follows it), any name after a title (Mr, Dr, Mme...), and any capitalised
// value after a key such as "name:", "customer:", "author=".
func findNames(text string) []Hit {
	var hits []Hit
	addHit := func(s int, v string) {
		v = trimNameWords(v)
		if v != "" {
			hits = append(hits, Hit{Start: s, End: s + len(v), Label: "NAME"})
		}
	}
	for _, m := range titleNameRe.FindAllStringSubmatchIndex(text, -1) {
		addHit(m[2], text[m[2]:m[3]])
	}
	for _, m := range keyNameRe.FindAllStringSubmatchIndex(text, -1) {
		addHit(m[2], text[m[2]:m[3]])
	}
	for _, m := range capWordRe.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		w := strings.TrimRight(text[s:e], "'’-")
		e = s + len(w)
		first := w
		if i := strings.IndexByte(w, '-'); i > 0 {
			first = w[:i] // Jean-Pierre, Mohamed-Amine
		}
		if isLetterAt(text, s, true) || !firstNameSet[strings.ToLower(accentFold.Replace(first))] {
			continue
		}
		if strings.ToUpper(w) == w && len(w) > 1 {
			continue // "JEAN" in an all-caps line is too noisy
		}
		if sm := surnameRe.FindStringIndex(text[e:]); sm != nil {
			if full := trimNameWords(text[s : e+sm[1]]); full != "" {
				addHit(s, full)
				continue
			}
		}
		hits = append(hits, Hit{Start: s, End: e, Label: "NAME"})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Start < hits[j].Start })
	return hits
}
