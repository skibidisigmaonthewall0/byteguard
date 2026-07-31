import { LanguageSupport, StreamLanguage } from "@codemirror/language";
import { properties as parser } from "@codemirror/legacy-modes/mode/properties";

export const properties = (): LanguageSupport => {
    return new LanguageSupport(StreamLanguage.define(parser));
};
