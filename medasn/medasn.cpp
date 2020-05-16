#include <iostream>
#include <string>

#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>

//#include "grammar/asn1.hpp"

namespace peg = tao::pegtl;

namespace {

//C++ keywords
std::set< std::string > keywords = {
	"alignas",
	"alignof",
	"and",
	"and_eq",
	"asm",
	"auto",
	"bitand",
	"bitor",
	"bool",
	"break",
	"case",
	"catch",
	"char",
	"char8_t",
	"char16_t",
	"char32_t",
	"class",
	"compl",
	"const",
	"consteval",
	"constexpr",
	"const_init",
	"const_cast",
	"continue",
	"co_await",
	"co_return",
	"co_yield",
	"decltype",
	"default",
	"delete",
	"do",
	"double",
	"dynamic_cast",
	"else",
	"enum",
	"explicit",
	"export",
	"extern",
	"false",
	"float",
	"for",
	"friend",
	"goto",
	"if",
	"inline",
	"int",
	"long",
	"mutable",
	"namespace",
	"new",
	"noexcept",
	"not",
	"not_eq",
	"nullptr",
	"operator",
	"or",
	"or_eq",
	"private",
	"protected",
	"public",
	"register",
	"reinterpret_cast",
	"return",
	"requires",
	"short",
	"signed",
	"sizeof",
	"static",
	"static_assert",
	"static_cast",
	"struct",
	"switch",
	"template",
	"this",
	"thread_local",
	"throw",
	"true",
	"try",
	"typedef",
	"typeid",
	"typename",
	"union",
	"unsigned",
	"using",
	"virtual",
	"void",
	"volatile",
	"wchar_t",
	"while",
	"xor",
	"xor_eq"
};

}

namespace asn1 {

struct comment : peg::disable< peg::two<'-'>, peg::until< peg::eolf > > {};
struct ws : peg::sor< peg::ascii::space, comment > {};
struct sp : peg::star< ws > {};
struct msp : peg::plus< ws > {};
struct newline : peg::sor< peg::one<'\n'>, peg::one<'\v'>, peg::one<'\f'>, peg::one<'\r'> > {};

struct letter : peg::sor< peg::ascii::upper, peg::ascii::lower > {};
struct dquote : peg::one<'"'> {};
struct squote : peg::one<'\''> {};
struct ref    : peg::one<'&'> {};
struct minus : peg::seq< sp, peg::one<'-'>, sp > {};
struct plus : peg::seq< sp, peg::one<'+'>, sp > {};
struct comma : peg::seq< sp, peg::one<','>, sp > {};
struct dot : peg::seq< sp, peg::one<'.'>, sp > {};
struct lparen : peg::seq< sp, peg::one<'('>, sp > {};
struct rparen : peg::seq< sp, peg::one<')'>, sp > {};
struct lbrace : peg::seq< sp, peg::one<'{'>, sp > {};
struct rbrace : peg::seq< sp, peg::one<'}'>, sp > {};
struct lbracket : peg::seq< sp, peg::one<'['>, sp > {};
struct rbracket : peg::seq< sp, peg::one<']'>, sp > {};
struct semicolon : peg::seq< sp, peg::one<';'>, sp > {};
struct colon : peg::seq< sp, peg::one<':'>, sp > {};
struct ellipsis : peg::three<'.'> {};
struct asn1ment : peg::seq< sp, peg::string<':',':','='>, sp > {};
struct OptionalExtensionMarker : peg::seq< comma, ellipsis > {};

using identifier_other = peg::internal::ranges<peg::internal::peek_char,'a','z','A','Z','0','9','-'>;

/* X.681 (08/2015) 10.6 A "word" token used as a "Literal" shall not be one of the following:
BIT
BOOLEAN
CHARACTER
CHOICE
DATE
DATE-TIME
DURATION
EMBEDDED
END
ENUMERATED
EXTERNAL
FALSE
INSTANCE
INTEGER
INTERSECTION
MINUS-INFINITY
NULL
OBJECT
OCTET
PLUS-INFINITY
REAL
RELATIVE-OID
SEQUENCE
SET
TIME
TIME-OF-DAY
TRUE
UNION
*/
struct Word : identifier_other {};
struct Literal : peg::sor< Word, peg::one<','> > {};

struct typereference : peg::seq< peg::ascii::upper, peg::star<identifier_other> > {};
struct identifier : peg::seq< peg::ascii::lower, peg::star<identifier_other> > {};
struct valuereference : identifier {};
struct modulereference : typereference {};

struct non_zero_digit : peg::range<'1','9'> {};
struct positive_number : peg::seq< non_zero_digit, peg::star< peg::ascii::digit > > {};
struct number : peg::sor< peg::one<'0'>, positive_number > {};
struct mantissa : peg::sor<
		peg::seq< positive_number,
			peg::opt< peg::seq< peg::one<'.'>, peg::star<peg::ascii::digit> > >
		>,
		peg::seq< peg::string<'0','.'>, peg::star< peg::one<'0'> >, positive_number > > {};
struct exponent : peg::seq< peg::istring<'E'>, peg::sor< peg::one<'0'>, peg::seq< peg::opt< peg::one<'-'> >, positive_number > > > {};
struct realnumber : peg::seq< mantissa, exponent > {};

struct bstring : peg::seq< squote, peg::star< peg::sor< peg::string<'B','I','T'>, ws > >, squote, peg::one<'B'> > {};
struct hstring : peg::seq< squote, peg::star< peg::sor< peg::ascii::xdigit, ws > >, squote, peg::one<'H'> > {};
struct cstring : peg::seq< dquote, peg::star< peg::ascii::any >, dquote > {};

struct DEFAULT  : peg::seq<sp, peg::string<'D','E','F','A','U','L','T'>    , sp> {};
struct OF       : peg::seq<sp, peg::string<'O','F'>                        , sp> {};
struct OPTIONAL : peg::seq<sp, peg::string<'O','P','T','I','O','N','A','L'>, sp> {};
struct SEQUENCE : peg::seq<sp, peg::string<'S','E','Q','U','E','N','C','E'>, sp> {};
struct SET      : peg::seq<sp, peg::string<'S','E','T'>                    , sp> {};

struct encodingreference : peg::seq< peg::ascii::upper, peg::star< peg::sor< peg::ascii::upper, peg::ascii::digit, minus > > > {};
struct objectclassreference : encodingreference {};


struct DefinitiveNumberForm : number {};
struct NameForm : identifier {};
struct DefinitiveNameAndNumberForm : peg::seq< identifier, lparen, DefinitiveNumberForm, rparen > {};
struct DefinitiveObjIdComponent : peg::sor< NameForm, DefinitiveNumberForm, DefinitiveNameAndNumberForm > {};
struct DefinitiveObjIdComponentList : peg::sor< DefinitiveObjIdComponent, peg::seq< DefinitiveObjIdComponent, msp, DefinitiveObjIdComponentList > > {};
struct DefinitiveOID : peg::seq< lbrace, DefinitiveObjIdComponentList, rbrace > {};

struct ArcIdentifier : peg::sor< peg::ascii::digit, peg::ascii::alnum > {};
struct IRIValue : peg::seq< dquote, peg::plus< peg::one<'/'>, ArcIdentifier >, dquote > {};
struct DefinitiveOIDandIRI : peg::seq< DefinitiveOID, msp, IRIValue > {};
struct DefinitiveIdentification : peg::sor< DefinitiveOID, DefinitiveOIDandIRI > {};

struct EncodingReferenceDefault : peg::seq< encodingreference, peg::string<'I','N','S','T','R','U','C','T','I','O','N','S'> > {};
struct EXPLICIT : peg::string<'E','X','P','L','I','C','I','T'> {};
struct IMPLICIT : peg::string<'I','M','P','L','I','C','I','T'> {};
struct AUTOMATIC: peg::string<'A','U','T','O','M','A','T','I','C'> {};
struct TagDefault : peg::seq< peg::sor<EXPLICIT, IMPLICIT, AUTOMATIC>, msp, peg::string<'T','A','G','S'> > {};

struct Reference : peg::sor< typereference, valuereference, objectclassreference > {};
struct ParameterizedReference : peg::seq< Reference, peg::opt< peg::seq< lbrace, rbrace > > > {};
struct Symbol : peg::sor< Reference, ParameterizedReference > {};
struct SymbolList : peg::list_must< Symbol, comma > {};
struct SymbolsExported : SymbolList {};
struct Exports : peg::seq< peg::string<'E','X','P','O','R','T','S'>,
		peg::sor< peg::string<'A','L','L'>, peg::opt< SymbolsExported > >, semicolon > {};

struct ExternalValueReference : peg::seq< modulereference, dot, valuereference > {};
struct DefinedValue : peg::sor< ExternalValueReference, valuereference > {};
struct NumberForm : peg::sor< number, DefinedValue > {};
struct NameAndNumberForm : peg::seq< identifier, lparen, NumberForm, rparen > {};
struct ObjIdComponents : peg::sor< NameForm, NumberForm, NameAndNumberForm, DefinedValue > {};
struct ObjIdComponentsList : peg::plus< sp, ObjIdComponents > {};
struct ObjectIdentifierValue : peg::seq< lbrace, peg::opt< peg::seq< DefinedValue, msp > >, ObjIdComponentsList, rbrace > {};
struct AssignedIdentifier : peg::sor< ObjectIdentifierValue, DefinedValue > {};
struct GlobalModuleReference : peg::seq< modulereference, peg::opt< AssignedIdentifier > > {};
struct SymbolsFromModule : peg::seq< SymbolList, peg::string<'F','R','O','M'>, msp, GlobalModuleReference > {};
struct SymbolsFromModuleList : peg::star<SymbolsFromModule> {};
struct SymbolsImported : SymbolsFromModuleList {};
struct Imports : peg::seq< peg::string<'I','M','P','O','R','T','S'>, peg::opt< SymbolsImported >, semicolon > {};


struct NamedBit : peg::sor< peg::seq< identifier, lparen, number, rparen >, peg::seq< identifier, lparen, DefinedValue, rparen > > {};
struct NamedBitList : peg::list_must<NamedBit, comma> {};
struct BitStringType : peg::seq<
		peg::string<'B','I','T'>, msp, peg::string<'S','T','R','I','N','G'>, peg::opt< peg::seq<lbrace, NamedBitList, rbrace> > > {};
struct BooleanType : peg::string<'B','O','O','L','E','A','N'> {};
struct RestrictedCharacterStringType : peg::sor<
		peg::string<'B','M','P','S','t','r','i','n','g'>,
		peg::string<'G','e','n','e','r','a','l','S','t','r','i','n','g'>,
		peg::string<'G','r','a','p','h','i','c','S','t','r','i','n','g'>,
		peg::string<'I','A','5','S','t','r','i','n','g'>,
		peg::string<'I','S','O','6','4','6','S','t','r','i','n','g'>,
		peg::string<'N','u','m','e','r','i','c','S','t','r','i','n','g'>,
		peg::string<'P','r','i','n','t','a','b','l','e','S','t','r','i','n','g'>,
		peg::string<'T','e','l','e','t','e','x','S','t','r','i','n','g'>,
		peg::string<'T','6','1','S','t','r','i','n','g'>,
		peg::string<'U','n','i','v','e','r','s','a','l','S','t','r','i','n','g'>,
		peg::string<'U','T','F','8','S','t','r','i','n','g'>,
		peg::string<'V','i','d','e','o','t','e','x','S','t','r','i','n','g'>,
		peg::string<'V','i','s','i','b','l','e','S','t','r','i','n','g'> > {};
struct UnrestrictedCharacterStringType : peg::seq<
		peg::string<'C','H','A','R','A','C','T','E','R'>, msp, peg::string<'S','T','R','I','N','G'>> {};
struct CharacterStringType : peg::sor< RestrictedCharacterStringType, UnrestrictedCharacterStringType > {};

struct Type;
struct NamedType : peg::seq< identifier, msp, Type > {};
struct Class : peg::seq<sp, peg::opt< peg::sor<
		peg::string<'U','N','I','V','E','R','S','A','L'>,
		peg::string<'A','P','P','L','I','C','A','T','I','O','N'>,
		peg::string<'P','R','I','V','A','T','E'> > >, sp > {};
struct ClassNumber : peg::sor< number, DefinedValue > {};
struct Tag : peg::seq< lbracket, peg::opt< peg::seq< encodingreference, colon > >, peg::opt< Class >, ClassNumber, rbracket > {};
struct TaggedType : peg::seq< Tag, peg::opt< peg::sor<
		peg::string<'I','M','P','L','I','C','I','T'>,
		peg::string<'E','X','P','L','I','C','I','T'> > >, msp, Type > {};
struct AlternativeTypeList : peg::sor< peg::list_must<NamedType, comma>, peg::list_must<TaggedType, comma> > {};
struct SignedNumber : peg::seq< peg::opt< peg::one<'-'> >, number > {};

struct objectreference : valuereference {};
struct ExternalObjectReference : peg::seq< modulereference, dot, objectreference > {};
struct DefinedObject : peg::sor< ExternalObjectReference, objectreference > {};
struct Value;
struct ValueSet;
struct DefinedObjectClass;
struct typefieldreference : peg::seq< ref, typereference> {};
struct valuefieldreference : peg::seq< ref, valuereference> {};
struct valuesetfieldreference : peg::seq< ref, typereference> {};
struct objectfieldreference : peg::seq< ref, objectreference> {};
struct objectsetreference : typereference {};
struct objectsetfieldreference : peg::seq< ref, objectsetreference> {};
struct PrimitiveFieldName : peg::sor<
		typefieldreference,
		valuefieldreference,
		valuesetfieldreference,
		objectfieldreference,
		objectsetfieldreference > {};

struct Object;

struct ContainedSubtype : peg::seq< peg::opt< peg::seq< peg::string<'I','N','C','L','U','D','E','S'>, msp > >, Type > {};
struct LowerEndValue : peg::sor< Value, peg::string<'M','I','N'> > {};
struct UpperEndValue : peg::sor< Value, peg::string<'M','A','X'> > {};
struct LowerEndpoint : peg::seq< LowerEndValue, peg::opt<peg::one<'<'>> > {};
struct UpperEndpoint : peg::seq< peg::opt<peg::one<'<'>>, UpperEndValue > {};
struct ValueRange : peg::seq< LowerEndpoint, peg::two<'.'>, UpperEndpoint > {};
struct ElementSetSpecs;
struct Governor : peg::sor< Type, DefinedObjectClass > {};
struct ExternalObjectSetReference : peg::seq< modulereference, dot, objectsetreference > {};
struct DefinedObjectSet : peg::sor< ExternalObjectSetReference, objectsetreference > {};
struct UserDefinedConstraintParameter : peg::sor<
		peg::seq< Governor, colon, Value >,
		peg::seq< Governor, colon, Object >,
		DefinedObjectSet,
		Type,
		DefinedObjectClass
> {};
struct UserDefinedConstraint : peg::seq< peg::string<'C','O','N','S','T','R','A','I','N','E','D'>, msp, peg::string<'B','Y'>,
		lbrace, peg::opt<peg::list_must<UserDefinedConstraintParameter, comma>>, rbrace > {};
struct Elements;
struct Exclusions : peg::seq< peg::string<'E','X','C','E','P','T'>, Elements > {};
struct IntersectionElements : peg::seq< Elements, peg::opt< Exclusions > > {};
struct IntersectionMark : peg::sor< peg::one<'^'>, peg::string<'I','N','T','E','R','S','E','C','T','I','O','N'> > {};
struct Intersections : peg::sor< IntersectionElements, peg::seq< Intersections, IntersectionMark, IntersectionElements > > {};
struct UnionMark : peg::sor< peg::one<'|'>, peg::string<'U','N','I','O','N'> > {};
struct Unions : peg::sor< Intersections, peg::seq< Unions, UnionMark, Intersections > > {};
struct ElementSetSpec : peg::sor< Unions, peg::seq< peg::string<'A','L','L'>, Exclusions > > {};
struct RootElementSetSpec : ElementSetSpec {};
struct ObjectSetSpec : peg::sor<
		RootElementSetSpec,
		peg::seq< peg::opt_must<RootElementSetSpec, comma>, ellipsis, peg::opt_must<comma, ElementSetSpec>>
> {};
struct ObjectSet : peg::seq< lbrace, ObjectSetSpec, rbrace > {};
struct SimpleTableConstraint : ObjectSet {};
struct ComponentIdList : peg::seq< identifier, peg::star< dot, identifier > > {};
struct AtNotation : peg::sor<
		peg::seq< peg::one<'@'>, sp, ComponentIdList >,
		peg::seq< peg::string<'@','.'>, peg::star<peg::one<'.'>>, sp, ComponentIdList > > {};
struct ComponentRelationConstraint : peg::seq<lbrace, DefinedObjectSet, rbrace, lbrace, peg::list_must<AtNotation, comma>, rbrace > {};
struct TableConstraint : peg::sor< SimpleTableConstraint, ComponentRelationConstraint > {};

struct CONTAINING : peg::string<'C','O','N','T','A','I','N','I','N','G'> {};
struct ENCODED_BY : peg::seq<peg::string<'E','N','C','O','D','E','D'>, msp, peg::string<'B','Y'>> {};
struct ContentsConstraint : peg::sor<
		peg::seq<CONTAINING, msp, Type>,
		peg::seq<ENCODED_BY, msp, Value>,
		peg::seq<CONTAINING, msp, Type, ENCODED_BY, msp, Value>
> {};
struct GeneralConstraint : peg::sor< UserDefinedConstraint, TableConstraint, ContentsConstraint > {};
struct ConstraintSpec : peg::sor< ElementSetSpecs, GeneralConstraint > {};
struct ExceptionIdentification : peg::sor< SignedNumber, DefinedValue, peg::seq< Type, colon, Value > > {};
struct ExceptionSpec : peg::opt< peg::seq< peg::one<'!'>, ExceptionIdentification > > {};
struct Constraint : peg::seq< lparen, ConstraintSpec, ExceptionSpec, rparen > {};
struct PermittedAlphabet : peg::seq< peg::string<'F','R','O','M'>, msp, Constraint > {};
struct SizeConstraint : peg::seq< peg::string<'S','I','Z','E'>, msp, Constraint > {};
struct TypeConstraint;
struct SingleTypeConstraint : Constraint {};
struct ValueConstraint : peg::opt< Constraint > {};
struct PresenceConstraint : peg::opt< peg::sor< peg::string<'P','R','E','S','E','N','T'>, peg::string<'A','B','S','E','N','T'>, OPTIONAL > > {};
struct ComponentConstraint : peg::seq< ValueConstraint, PresenceConstraint > {};
struct NamedConstraint : peg::seq< identifier, ComponentConstraint > {};
struct TypeConstraints : peg::sor< NamedConstraint, peg::seq< NamedConstraint, comma, TypeConstraints > > {};
struct FullSpecification : peg::seq< lbrace, TypeConstraints, rbrace > {};
struct PartialSpecification : peg::seq< lbrace, ellipsis, comma, TypeConstraints, rbrace > {};
struct MultipleTypeConstraints : peg::sor< FullSpecification, PartialSpecification > {};

struct WITH : peg::string<'W','I','T','H'> {};
struct InnerTypeConstraints : peg::sor<
		peg::seq< WITH, msp, peg::string<'C','O','M','P','O','N','E','N','T'>, msp, SingleTypeConstraint >,
		peg::seq< WITH, msp, peg::string<'C','O','M','P','O','N','E','N','T','S'>, MultipleTypeConstraints >
> {};
struct PatternConstraint : peg::seq< peg::string<'P','A','T','T','E','R','N'>, Value > {};
struct simplestring : peg::seq< dquote, peg::plus< peg::sor< peg::range< 0x20, 0x21 >, peg::range< 0x23, 0x7E > > >, dquote > {};
struct PropertySettings : peg::seq< peg::string<'S','E','T','T','I','N','G','S'>, simplestring > {};
struct DurationRange : ValueRange {};
struct TimePointRange : ValueRange {};
struct RecurrenceRange : ValueRange {};
struct SubtypeElements : peg::sor<
		Value,
		ContainedSubtype,
		ValueRange,
		PermittedAlphabet,
		SizeConstraint,
		TypeConstraint,
		InnerTypeConstraints,
		PatternConstraint,
		PropertySettings,
		DurationRange,
		TimePointRange,
		RecurrenceRange
> {};

struct Object;
struct Setting : peg::sor< Type, Value, ValueSet, Object, ObjectSet > {};
struct FieldSetting : peg::seq< PrimitiveFieldName, Setting > {};
struct DefaultSyntax : peg::seq< lbrace, peg::list_must<FieldSetting, comma>, rbrace > {};
struct DefinedSyntaxToken : peg::sor< Literal, Setting > {};
struct DefinedSyntax : peg::seq< lbrace, peg::star< DefinedSyntaxToken >, rbrace > {};
struct ObjectDefn : peg::sor< DefaultSyntax, DefinedSyntax > {};
struct ActualParameter : peg::sor< Type, Value, ValueSet, DefinedObjectClass, Object, ObjectSet > {};
struct ActualParameterList : peg::seq< lbrace, peg::list_must<ActualParameter, comma>, rbrace > {};
struct ParameterizedObject : peg::seq< DefinedObject, ActualParameterList > {};
struct ParameterizedObjectSet : peg::seq< DefinedObjectSet, ActualParameterList > {};
struct ReferencedObjects : peg::sor< DefinedObject, ParameterizedObject, DefinedObjectSet, ParameterizedObjectSet > {};
struct FieldName : peg::list_must<PrimitiveFieldName, dot> {};
struct ObjectFromObject : peg::seq< ReferencedObjects, dot, FieldName > {};
struct Object : peg::sor< DefinedObject, ObjectDefn, ObjectFromObject, ParameterizedObject > {};
struct ObjectSetFromObjects : peg::seq< ReferencedObjects, dot, FieldName > {};
struct ObjectSetElements : peg::sor< Object, DefinedObjectSet, ObjectSetFromObjects, ParameterizedObjectSet > {};
struct Elements : peg::sor< SubtypeElements, ObjectSetElements, peg::seq< lparen, ElementSetSpec, rparen > > {};
struct ValueFromObject : peg::seq< ReferencedObjects, dot, FieldName > {};
struct ReferencedValue : peg::sor< DefinedValue, ValueFromObject > {};
struct BuiltinValue;
struct OpenTypeFieldVal : peg::seq< Type, colon, Value > {};
struct FixedTypeFieldVal : peg::sor< BuiltinValue, ReferencedValue > {};
struct ObjectClassFieldValue : peg::sor< OpenTypeFieldVal, FixedTypeFieldVal > {};
struct Value : peg::sor< BuiltinValue, ReferencedValue, ObjectClassFieldValue > {};
struct SingleValue : Value {};
struct ExtensionAndException : peg::seq< ellipsis, sp, peg::opt< ExceptionSpec > > {};
struct VersionNumber : peg::seq< number, colon > {};
struct ExtensionAdditionAlternativesGroup : peg::seq< peg::two<'['>, sp, VersionNumber, AlternativeTypeList, sp, peg::two<']'> > {};
struct ExtensionAdditionAlternative : peg::sor< ExtensionAdditionAlternativesGroup, NamedType > {};
struct ExtensionAdditionAlternativesList : peg::list_must<ExtensionAdditionAlternative, comma> {};
struct AlternativeTypeLists : peg::sor< AlternativeTypeList,
		peg::seq< AlternativeTypeList, comma, ExtensionAndException,
			peg::opt< peg::seq< comma, ExtensionAdditionAlternativesList > >, peg::opt< OptionalExtensionMarker > > > {};
struct ChoiceType : peg::seq< peg::string<'C','H','O','I','C','E'>, lbrace, AlternativeTypeLists, rbrace > {};
struct DateType : peg::string<'D','A','T','E'> {};
struct DateTimeType : peg::string<'D','A','T','E','-','T','I','M','E'> {};
struct DurationType : peg::string<'D','U','R','A','T','I','O','N'> {};
struct EmbeddedPDVType : peg::seq< peg::string<'E','M','B','E','D','D','E','D'>, msp, peg::string<'P','D','V'> > {};
struct NamedNumber : peg::sor< peg::seq< identifier, lparen, SignedNumber, rparen >, peg::seq< identifier, lparen, DefinedValue, rparen > > {};
struct EnumerationItem : peg::sor< identifier, NamedNumber > {};
struct Enumeration : peg::list_must<EnumerationItem, comma> {};
struct RootEnumeration : Enumeration {};
struct AdditionalEnumeration : Enumeration {};
struct Enumerations : peg::seq< RootEnumeration, peg::opt<
		peg::seq<comma, ellipsis, ExceptionSpec>,
		peg::opt< peg::seq<comma, AdditionalEnumeration> > > > {};
struct EnumeratedType : peg::seq< peg::string<'E','N','U','M','E','R','A','T','E','D'>, lbrace, Enumerations, rbrace > {};
struct ExternalType : peg::string<'E','X','T','E','R','N','A','L'> {};
struct ExternalObjectClassReference : peg::seq< modulereference, dot, objectclassreference > {};
struct UsefulObjectClassReference : peg::sor<
		peg::string<'T','Y','P','E','-','I','D','E','N','T','I','F','I','E','R'>,
		peg::string<'A','B','S','T','R','A','C','T','-','S','Y','N','T','A','X'> > {};
struct DefinedObjectClass : peg::sor< ExternalObjectClassReference, objectclassreference, UsefulObjectClassReference > {};
struct InstanceOfType : peg::seq< peg::string<'I','N','S','T','A','N','C','E'>, OF, DefinedObjectClass > {};
struct NamedNumberList : peg::list_must<NamedNumber, comma> {};
struct IntegerType : peg::seq< peg::string<'I','N','T','E','G','E','R'>, peg::opt< peg::seq< lbrace, NamedNumberList, rbrace > > > {};
struct IRIType : peg::string<'O','I','D','-','I','R','I'> {};
struct NullType : peg::string<'N','U','L','L'> {};

struct ObjectClassFieldType : peg::seq< DefinedObjectClass, dot, FieldName > {};
struct ObjectIdentifierType : peg::seq<
		peg::string<'O','B','J','E','C','T'>, msp, peg::string<'I','D','E','N','T','I','F','I','E','R'> > {};
struct OctetStringType : peg::seq< peg::string<'O','C','T','E','T'>, msp, peg::string<'S','T','R','I','N','G'> > {};
struct RealType : peg::string<'R','E','A','L'> {};
struct RelativeIRIType : peg::string<'R','E','L','A','T','I','V','E','-','O','I','D','-','I','R','I'> {};
struct RelativeOIDType : peg::string<'R','E','L','A','T','I','V','E','-','O','I','D'> {};

struct ComponentType : peg::sor<
		peg::seq<NamedType, peg::opt<msp, peg::sor<OPTIONAL, peg::seq<DEFAULT, msp, Value>>>>,
		peg::seq<peg::string<'C','O','M','P','O','N','E','N','T','S'>, msp, OF, msp, Type>
> {};
struct ComponentTypeList : peg::list_must<ComponentType, comma> {};
struct RootComponentTypeList : ComponentTypeList {};
struct ExtensionAdditionGroup : peg::seq< peg::two<'['>, sp, peg::opt<VersionNumber>, sp, ComponentTypeList, sp, peg::two<']'> > {};
struct ExtensionAddition : peg::sor< ComponentType, ExtensionAdditionGroup > {};
struct ExtensionAdditionList : peg::seq< peg::opt_must<ExtensionAdditionList, comma>, ExtensionAddition> {};
struct ExtensionAdditions : peg::seq< comma, ExtensionAdditionList > {};
struct ExtensionEndMarker : peg::seq< comma, ellipsis > {};
struct ComponentTypeLists : peg::sor<
		RootComponentTypeList,
		peg::seq< RootComponentTypeList, comma, ExtensionAndException, sp,
			peg::opt<ExtensionAdditions, sp, OptionalExtensionMarker> >,
		peg::seq< RootComponentTypeList, comma, ExtensionAndException, sp,
			peg::opt<ExtensionAdditions>, sp, ExtensionEndMarker, comma, RootComponentTypeList >,
		peg::seq< ExtensionAndException, sp, peg::opt<ExtensionAdditions>, sp, ExtensionEndMarker, comma, RootComponentTypeList >,
		peg::seq< ExtensionAndException, sp, peg::opt<ExtensionAdditions, sp, OptionalExtensionMarker> >
> {};
struct SequenceType : peg::seq< SEQUENCE, lbrace,
		peg::opt< peg::sor<
			peg::seq< ExtensionAndException, peg::opt<OptionalExtensionMarker> >,
			ComponentTypeLists > >,
		rbrace > {};
struct SetType : peg::seq< SET, lbrace,
		peg::opt< peg::sor<
			peg::seq< ExtensionAndException, peg::opt<OptionalExtensionMarker> >,
			ComponentTypeLists
		>>, rbrace > {};
struct SetOfType : peg::seq< SET, msp, OF, msp, peg::sor< Type, NamedType > > {};

struct EncodingInstruction : peg::disable< peg::one<'['>, peg::until<peg::one<']'>> > {};
struct EncodingPrefix : peg::seq< lbracket, peg::opt<encodingreference, colon>, EncodingInstruction, rbracket > {};
struct EncodingPrefixedType : peg::seq< EncodingPrefix, Type > {};
struct PrefixedType : peg::sor< TaggedType, EncodingPrefixedType > {};
struct SequenceOfType : peg::sor< peg::seq< SEQUENCE, OF, Type >, peg::seq< SEQUENCE, OF, NamedType > > {};
struct TimeType : peg::string<'T','I','M','E'> {};
struct TimeOfDayType : peg::string<'T','I','M','E','-','O','F','-','D','A','Y'> {};
struct BuiltinType : peg::sor<
		BitStringType,
		BooleanType,
		CharacterStringType,
		ChoiceType,
		DateType,
		DateTimeType,
		DurationType,
		EmbeddedPDVType,
		EnumeratedType,
		ExternalType,
		InstanceOfType,
		IntegerType,
		IRIType,
		NullType,
		ObjectClassFieldType,
		ObjectIdentifierType,
		OctetStringType,
		RealType,
		RelativeIRIType,
		RelativeOIDType,
		SequenceType,
		SequenceOfType,
		SetType,
		SetOfType,
		PrefixedType,
		TimeType,
		TimeOfDayType
> {};

struct ExternalTypeReference : peg::seq< modulereference, dot, typereference > {};
struct SimpleDefinedType : peg::sor< ExternalTypeReference, typereference > {};
struct ElementSetSpecs : peg::sor<
		RootElementSetSpec,
		peg::seq< RootElementSetSpec, peg::one<','>, ellipsis >,
		peg::seq< RootElementSetSpec, peg::one<','>, ellipsis, peg::one<','>, ElementSetSpec >
> {};
struct ValueSet : peg::seq< lbrace, ElementSetSpecs, rbrace > {};

struct ParameterizedType : peg::seq< SimpleDefinedType, ActualParameterList > {};
struct ParameterizedValueSetType : peg::seq< SimpleDefinedType, ActualParameterList > {};
struct DefinedType : peg::sor< ExternalTypeReference, typereference, ParameterizedType, ParameterizedValueSetType > {};
struct SelectionType : peg::seq< identifier, sp, peg::one<'<'>, sp, Type > {};
struct UsefulType : typereference {};
struct TypeFromObject : peg::seq< ReferencedObjects, dot, FieldName > {};
struct ValueSetFromObjects : peg::seq< ReferencedObjects, dot, FieldName > {};
struct ReferencedType : peg::sor< DefinedType, UsefulType, SelectionType, TypeFromObject, ValueSetFromObjects > {};
struct ConstrainedType;
struct Type : peg::sor< BuiltinType, ReferencedType, ConstrainedType > {};
struct TypeConstraint : Type {};
struct TypeWithConstraint : peg::sor<
		peg::seq< SET, Constraint, OF, Type >,
		peg::seq< SET, msp, SizeConstraint, OF, Type >,
		peg::seq< SEQUENCE, msp, Constraint, OF, Type >,
		peg::seq< SEQUENCE, msp, SizeConstraint, OF, Type >,
		peg::seq< SET, Constraint, OF, NamedType >,
		peg::seq< SET, SizeConstraint, OF, NamedType >,
		peg::seq< SEQUENCE, Constraint, OF, NamedType >,
		peg::seq< SEQUENCE, SizeConstraint, OF, NamedType >
> {};
struct ConstrainedType : peg::sor< peg::seq< Type, Constraint >, TypeWithConstraint > {};

struct TypeAssignment : peg::seq< typereference, asn1ment, Type > {};
struct ValueAssignment : peg::seq< valuereference, msp, Type, asn1ment, Value > {};
struct ValueSetTypeAssignment : peg::seq< typereference, msp, Type, asn1ment, ValueSet > {};
struct TypeOptionalitySpec : peg::sor< OPTIONAL, peg::seq< DEFAULT, Type > > {};
struct TypeFieldSpec : peg::seq< typefieldreference, peg::opt< TypeOptionalitySpec > > {};
struct ValueOptionalitySpec : peg::sor< OPTIONAL, peg::seq< DEFAULT, Value > > {};
struct FixedTypeValueFieldSpec : peg::seq< valuefieldreference, Type,
		peg::opt<peg::string<'U','N','I','Q','U','E'>>, sp, peg::opt<ValueOptionalitySpec> > {};
struct VariableTypeValueFieldSpec : peg::seq< valuefieldreference, FieldName, peg::opt< ValueOptionalitySpec > > {};
struct ValueSetOptionalitySpec : peg::sor< OPTIONAL, peg::seq< DEFAULT, ValueSet > > {};
struct FixedTypeValueSetFieldSpec : peg::seq< valuesetfieldreference, Type, peg::opt< ValueSetOptionalitySpec > > {};
struct VariableTypeValueSetFieldSpec : peg::seq< valuesetfieldreference, FieldName, peg::opt< ValueSetOptionalitySpec > > {};
struct ObjectOptionalitySpec : peg::sor< OPTIONAL, peg::seq< DEFAULT, Object > > {};
struct ObjectFieldSpec : peg::seq< objectfieldreference, DefinedObjectClass, peg::opt< ObjectOptionalitySpec > > {};
struct ObjectSetOptionalitySpec : peg::sor< OPTIONAL, peg::seq< DEFAULT, ObjectSet > > {};
struct ObjectSetFieldSpec : peg::seq< objectsetfieldreference, DefinedObjectClass, peg::opt< ObjectSetOptionalitySpec > > {};

struct FieldSpec : peg::sor<
		TypeFieldSpec,
		FixedTypeValueFieldSpec,
		VariableTypeValueFieldSpec,
		FixedTypeValueSetFieldSpec,
		VariableTypeValueSetFieldSpec,
		ObjectFieldSpec,
		ObjectSetFieldSpec
> {};

// X.681 (08/2015) 10.5 really fkdup specs...
struct RequiredToken : peg::sor< Literal, PrimitiveFieldName > {};
struct OptionalGroup;
struct TokenOrGroupSpec : peg::sor< RequiredToken, OptionalGroup > {};
struct OptionalGroup : peg::seq< lbracket, peg::star< TokenOrGroupSpec >, rbracket > {};
struct SyntaxList : peg::seq< lbrace, peg::star< TokenOrGroupSpec >, rbrace > {};
struct WithSyntaxSpec : peg::seq< peg::string<'W','I','T','H'>, msp, peg::string<'S','Y','N','T','A','X'>, msp, SyntaxList > {};
struct ObjectClassDefn : peg::seq< peg::string<'C','L','A','S','S'>, lbrace,
		peg::list_must<FieldSpec, comma>,
		rbrace,
		peg::opt< WithSyntaxSpec > > {};
struct ParameterizedObjectClass : peg::seq< DefinedObjectClass, ActualParameterList > {};
struct ObjectClass : peg::sor<
		DefinedObjectClass,
		ObjectClassDefn,
		ParameterizedObjectClass
> {};

struct ObjectClassAssignment : peg::seq< objectclassreference, asn1ment, ObjectClass > {};
struct ObjectAssignment : peg::seq< objectreference, DefinedObjectClass, asn1ment, Object > {};
struct ObjectSetAssignment : peg::seq< objectsetreference, DefinedObjectClass, asn1ment, ObjectSet > {};
struct DummyReference : Reference {};
struct DummyGovernor : Reference {};
struct ParamGovernor : peg::sor< Governor, DummyGovernor > {};
struct Parameter : peg::sor< peg::seq< ParamGovernor, colon, DummyReference >, DummyReference > {};
struct ParameterList : peg::seq< lbrace, peg::list_must<Parameter, comma>, rbrace > {};
struct ParameterizedTypeAssignment : peg::seq< typereference, ParameterList, asn1ment, Type > {};
struct ParameterizedValueAssignment : peg::seq< valuereference, ParameterList, Type, asn1ment, Value > {};
struct ParameterizedValueSetTypeAssignment : peg::seq< typereference, ParameterList, Type, asn1ment, ValueSet > {};
struct ParameterizedObjectClassAssignment : peg::seq< objectclassreference, ParameterList, asn1ment, ObjectClass > {};
struct ParameterizedObjectAssignment : peg::seq< objectreference, ParameterList, DefinedObjectClass, asn1ment, Object > {};
struct ParameterizedObjectSetAssignment : peg::seq< objectsetreference, ParameterList, DefinedObjectClass, asn1ment, ObjectSet > {};
struct ParameterizedAssignment : peg::sor<
		ParameterizedTypeAssignment,
		ParameterizedValueAssignment,
		ParameterizedValueSetTypeAssignment,
		ParameterizedObjectClassAssignment,
		ParameterizedObjectAssignment,
		ParameterizedObjectSetAssignment
> {};
struct Assignment : peg::sor<
		TypeAssignment,
		ValueAssignment,
		ValueSetTypeAssignment,
		ObjectClassAssignment,
		ObjectAssignment,
		ObjectSetAssignment,
		ParameterizedAssignment
> {};
struct AssignmentList : peg::plus< sp, Assignment > {};

struct ModuleBody : peg::seq< peg::opt< Exports >, msp, peg::opt< Imports >, msp, AssignmentList > {};
struct ModuleIdentifier : peg::seq< modulereference, peg::opt< DefinitiveIdentification > > {};
//X.680 (08/2015) 54.4
struct ENCODING_CONTROL : peg::string<'E','N','C','O','D','I','N','G','-','C','O','N','T','R','O','L'> {};
struct END : peg::string<'E','N','D'> {};
struct EncodingInstructionAssignmentList : peg::disable< peg::any, peg::until<peg::sor<ENCODING_CONTROL, END>>> {};
struct EncodingControlSection : peg::seq< ENCODING_CONTROL, encodingreference, EncodingInstructionAssignmentList > {};
struct EncodingControlSections : peg::star< EncodingControlSection > {};
struct ModuleDefinition : peg::seq<
	ModuleIdentifier,
	peg::string<'D','E','F','I','N','I','T','I','O','N','S'>,
	peg::opt< EncodingReferenceDefault >,
	peg::opt< TagDefault >,
	peg::opt< peg::seq< peg::string<'E','X','T','E','N','S','I','B','I','L','I','T','Y'>, msp, peg::string<'I','M','P','L','I','E','D'> > >,
	asn1ment, peg::string<'B','E','G','I','N'>,
	peg::opt< ModuleBody >,
	EncodingControlSections,
	peg::string<'E','N','D'>
> {};


struct BitStringValue : peg::sor<
		bstring,
		hstring,
		peg::seq<lbrace, peg::opt<peg::list_must<identifier, comma>>, rbrace>,
		peg::seq<peg::string<'C','O','N','T','A','I','N','I','N','G'>, msp, Value>
> {};
struct BooleanValue : peg::sor< peg::string<'T','R','U','E'>, peg::string<'F','A','L','S','E'> > {};
struct Group : number {};
struct Plane : number {};
struct Row : number {};
struct Cell : number {};
struct Quadruple : peg::seq< lbrace, Group, comma, Plane, comma, Row, comma, Cell, rbrace > {};
struct TableColumn : number {};
struct TableRow : number {};
struct Tuple : peg::seq< lbrace, TableColumn, comma, TableRow, rbrace > {};
struct CharsDefn : peg::sor< cstring, Quadruple, Tuple, DefinedValue > {};
struct CharSyms : peg::list_must<CharsDefn, comma> {};
struct CharacterStringList : peg::seq< lbrace, CharSyms, rbrace > {};
struct RestrictedCharacterStringValue : peg::sor< cstring, CharacterStringList, Quadruple, Tuple > {};
struct NamedValue : peg::seq< identifier, msp, Value > {};
struct ComponentValueList : peg::list_must<NamedValue, comma> {};
struct SequenceValue : peg::seq< lbrace, peg::opt< ComponentValueList >, rbrace > {};
struct UnrestrictedCharacterStringValue : SequenceValue {};
struct CharacterStringValue : peg::sor< RestrictedCharacterStringValue, UnrestrictedCharacterStringValue > {};
struct ChoiceValue : peg::seq< identifier, colon, Value > {};
struct EmbeddedPDVValue : SequenceValue {};
struct EnumeratedValue : identifier {};
struct ExternalValue : SequenceValue {};
struct InstanceOfValue : Value {};
struct IntegerValue : peg::sor< SignedNumber, identifier > {};
struct NullValue : peg::string<'N','U','L','L'> {};
struct OctetStringValue : peg::sor< bstring, hstring, peg::seq< peg::string<'C','O','N','T','A','I','N','I','N','G'>, msp, Value > > {};
struct SpecialRealValue : peg::sor< peg::string<'P','L','U','S','-','I','N','F','I','N','I','T','Y'>, peg::string<'M','I','N','U','S','-','I','N','F','I','N','I','T','Y'>, peg::string<'N','O','T','-','A','-','N','U','M','B','E','R'> > {};
struct RealSequenceValue : peg::seq< lbrace, peg::string<'m','a','n','t','i','s','s','a'>, msp, IntegerValue, comma, peg::string<'b','a','s','e'>, msp, peg::sor< peg::one<'2'>, peg::string<'1','0'> >, comma, peg::string<'e','x','p','o','n','e','n','t'>, msp, IntegerValue, rbrace > {};
struct NumericRealValue : peg::sor< peg::one<'0'>, realnumber, peg::seq< peg::one<'-'>, realnumber >, RealSequenceValue > {};
struct RealValue : peg::sor< NumericRealValue, SpecialRealValue > {};
struct RelativeIRIValue : peg::seq< dquote, ArcIdentifier, peg::star< peg::one<'/'>, ArcIdentifier >, dquote > {};
struct RelativeOIDComponents : peg::sor< NumberForm, NameAndNumberForm, DefinedValue > {};
struct RelativeOIDComponentsList : peg::plus< sp, RelativeOIDComponents > {};
struct RelativeOIDValue : peg::seq< lbrace, RelativeOIDComponentsList, rbrace > {};
struct ValueList : peg::list_must<Value, comma> {};
struct NamedValueList : peg::list_must<NamedValue, comma> {};
struct SequenceOfValue : peg::seq< lbrace, peg::opt< peg::sor< ValueList, NamedValueList > >, rbrace > {};
struct SetValue : peg::seq< lbrace, peg::opt< ComponentValueList >, rbrace > {};
struct SetOfValue : peg::seq< lbrace, peg::opt< peg::sor< ValueList, NamedValueList > >, rbrace > {};
struct PrefixedValue : Value {};
struct tstring : peg::seq<
	dquote,
		peg::plus<
			peg::sor<
				peg::ascii::digit, peg::one<'+'>, peg::one<'-'>, peg::one<':'>, peg::one<','>, peg::one<'/'>,
				peg::istring<'C'>, peg::istring<'D'>, peg::istring<'H'>, peg::istring<'M'>, peg::istring<'R'>,
				peg::istring<'P'>, peg::istring<'S'>, peg::istring<'T'>, peg::istring<'W'>, peg::istring<'Y'>,
				peg::istring<'Z'> > >,
	dquote
> {};
struct TimeValue : tstring {};
struct BuiltinValue : peg::sor<
		BitStringValue,
		BooleanValue,
		CharacterStringValue,
		ChoiceValue,
		EmbeddedPDVValue,
		EnumeratedValue,
		ExternalValue,
		InstanceOfValue,
		IntegerValue,
		IRIValue,
		NullValue,
		ObjectIdentifierValue,
		OctetStringValue,
		RealValue,
		RelativeIRIValue,
		RelativeOIDValue,
		SequenceValue,
		SequenceOfValue,
		SetValue,
		SetOfValue,
		PrefixedValue,
		TimeValue
> {};


struct grammar : peg::must< sp, ModuleDefinition, sp, peg::eof > {};

} //end: namespace asn1

int main(int argc, char** argv)
{

	if (argc != 2)
	{
		peg::analyze< asn1::grammar >();
		std::cerr << "Usage: " << argv[0] << " SOURCE" << std::endl;
		return EXIT_FAILURE;
	}

	peg::file_input<> in{argv[1]};

#if 0
	try
	{
		const auto root =
		peg::parse_tree::parse<asn1::grammar, asn1::selector, nothing, asn1::error_control >( in );
		for (auto const& rule : root->children)
		{
			abnf::rules_defined.push_back( asn1::get_rulename( rule->children.front() ) );
		}

		for (auto const& rule : root->children)
		{
			std::cout << asn1::to_string( rule ) << std::endl;
		}
	}
	catch (peg::parse_error const& ex)
	{
		const auto p = ex.positions.front();
		std::cerr << ex.what() << std::endl
				<< in.line_at(p) << std::endl
				<< std::string(p.byte_in_line,'') <<'^' << std::endl;
		return EXIT_FAILURE;
	}
#endif
	return EXIT_SUCCESS;
}
