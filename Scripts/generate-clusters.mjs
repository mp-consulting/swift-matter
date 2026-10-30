#!/usr/bin/env node
// Generates Sources/Matter/DataModel/Definitions.swift from the Matter model that matter.js generates from the
// specification: packages/model/src/standard/elements/*.element.ts of a project-chip/matter.js checkout. The files are
// read as text and parsed here; nothing from the checkout is executed.
//
//   node Scripts/generate-clusters.mjs <matter.js checkout> > Sources/Matter/DataModel/Definitions.swift

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const checkout = process.argv[2];
if (!checkout) {
    console.error("usage: generate-clusters.mjs <matter.js checkout>");
    process.exit(1);
}
const directory = join(checkout, "packages/model/src/standard/elements");

// A parser for the subset of JavaScript the element files use: calls of named element constructors whose arguments are
// object literals (strings, numbers, booleans, null, arrays, nested objects) and further calls.
function parse(source) {
    let index = 0;
    const space = () => {
        for (;;) {
            while (index < source.length && /\s/.test(source[index])) index++;
            if (source.startsWith("//", index)) index = source.indexOf("\n", index) + 1 || source.length;
            else if (source.startsWith("/*", index)) index = source.indexOf("*/", index) + 2;
            else return;
        }
    };
    const expect = character => {
        space();
        if (source[index] !== character) throw new Error(`expected ${character} at ${index}: ${source.slice(index, index + 40)}`);
        index++;
    };
    const identifier = () => {
        space();
        const match = /^[A-Za-z_$][\w$]*/.exec(source.slice(index));
        if (!match) throw new Error(`expected an identifier at ${index}`);
        index += match[0].length;
        return match[0];
    };
    const value = () => {
        space();
        const character = source[index];
        if (character === "{") return object();
        if (character === "[") {
            index++;
            const items = [];
            for (space(); source[index] !== "]"; space()) {
                items.push(value());
                space();
                if (source[index] === ",") index++;
            }
            index++;
            return items;
        }
        if (character === '"' || character === "'") {
            index++;
            let string = "";
            while (source[index] !== character) {
                if (source[index] === "\\") index++;
                string += source[index++];
            }
            index++;
            return string;
        }
        const number = /^-?(0x[0-9a-fA-F]+|\d+(\.\d+)?(e-?\d+)?)n?/.exec(source.slice(index));
        if (number) {
            index += number[0].length;
            return Number(number[0].replace(/n$/, ""));
        }
        const name = identifier();
        if (name === "true") return true;
        if (name === "false") return false;
        if (name === "null" || name === "undefined") return null;
        space();
        if (source[index] === "(") return call(name);
        return { $ref: name };
    };
    const object = () => {
        expect("{");
        const result = {};
        for (space(); source[index] !== "}"; space()) {
            space();
            const key = source[index] === '"' ? value() : identifier();
            expect(":");
            result[key] = value();
            space();
            if (source[index] === ",") index++;
        }
        index++;
        return result;
    };
    const call = name => {
        expect("(");
        const args = [];
        for (space(); source[index] !== ")"; space()) {
            args.push(value());
            space();
            if (source[index] === ",") index++;
        }
        index++;
        const [properties = {}, ...children] = args;
        return { kind: name, ...properties, children: children.filter(child => child && child.kind) };
    };
    return { call, identifier, seek: position => { index = position; } };
}

const elements = [];
for (const file of readdirSync(directory).filter(name => name.endsWith(".element.ts")).sort()) {
    const source = readFileSync(join(directory, file), "utf8");
    const match = /export const \w+ = (\w+)\(/.exec(source);
    if (!match) continue;
    const parser = parse(source);
    parser.seek(match.index + match[0].length - match[1].length - 1);
    const kind = parser.identifier();
    elements.push(parser.call(kind));
}

const kinds = kind => elements.filter(element => element.kind === kind);

// A derived cluster (`type: "ModeBase"`, `"OperationalState"`) lists only what it changes: it gets its base's
// elements, each overlaid with the derived one of the same kind and name, recursively, so attributes keep their types,
// access and qualities, and commands, events and datatypes the derived file leaves out are there.
const clustersByName = new Map(kinds("Cluster").map(cluster => [cluster.name, cluster]));
function overlay(base, derived) {
    const merged = { ...base, ...derived, children: mergeChildren(base.children ?? [], derived.children ?? []) };
    // A datatype that names itself as its type ("ModeOptionStruct" of type "ModeOptionStruct") is the base's.
    if (derived.type === derived.name) merged.type = base.type;
    return merged;
}
function mergeChildren(baseChildren, derivedChildren) {
    const key = child => `${child.kind}:${child.name}`;
    const own = new Map(derivedChildren.map(child => [key(child), child]));
    const merged = baseChildren.map(child => {
        const derived = own.get(key(child));
        if (!derived) return child;
        own.delete(key(child));
        return overlay(child, derived);
    });
    return merged.concat([...own.values()]);
}
function resolved(cluster) {
    const base = cluster.type && cluster.type !== cluster.name ? clustersByName.get(cluster.type) : undefined;
    return base ? { ...cluster, children: mergeChildren(resolved(base).children, cluster.children) } : cluster;
}
const childrenOf = (element, kind) => element.children.filter(child => child.kind === kind);
const hex = (value, width) => "0x" + value.toString(16).toUpperCase().padStart(width, "0");
/// UpperCamelCase of an element name.
const pascal = name => name.replace(/[^A-Za-z0-9]+/g, " ").trim().split(" ").map(word => word[0].toUpperCase() + word.slice(1)).join("");
const camel = name => {
    const joined = pascal(name);
    let result = joined.replace(/^[A-Z]+(?=[A-Z][a-z]|$)|^[A-Z]/, prefix => prefix.toLowerCase());
    if (/^\d/.test(result)) result = "_" + result;
    return SWIFT_KEYWORDS.has(result) ? "`" + result + "`" : result;
};
const SWIFT_KEYWORDS = new Set(["default", "repeat", "return", "switch", "case", "class", "struct", "enum", "init",
    "is", "as", "in", "for", "while", "if", "else", "do", "try", "catch", "throw", "public", "private", "internal",
    "static", "var", "let", "func", "import", "operator", "protocol", "extension", "self", "Self", "super", "true",
    "false", "nil", "where", "guard", "defer", "break", "continue", "fallthrough", "subscript", "typealias", "inout",
    "Type", "Protocol", "any", "some"]);

/// The Swift type of a cluster: its name in UpperCamelCase and "Cluster".
function typeNameOf(cluster) {
    return pascal(cluster.name) + "Cluster";
}

const privileges = { V: ".view", P: ".proxyView", O: ".operate", M: ".manage", A: ".administer" };

/// "R V", "RW VO", "R[W] VM", "R F A", "O T", "F A"...
function access(text, defaults) {
    const tokens = (text ?? "").split(/\s+/).filter(Boolean);
    let read = defaults.read, write = null, invoke = defaults.invoke, fabricScoped = false, sensitive = false, timed = false;
    let writable = false;
    for (const token of tokens) {
        if (/^R(\[?W\]?)?$/.test(token)) { writable = token.includes("W"); continue; }
        if (token === "W") { writable = true; continue; }
        if (token === "F") { fabricScoped = true; continue; }
        if (token === "S") { sensitive = true; continue; }
        if (token === "T") { timed = true; continue; }
        if (/^[VPOMA]+$/.test(token)) {
            const letters = token.split("");
            if (defaults.kind === "attribute") {
                read = privileges[letters[0]];
                // One letter for a read-write attribute ("RW F A") is both privileges.
                write = privileges[letters[letters.length > 1 ? 1 : 0]];
            } else {
                invoke = privileges[letters[0]];
            }
        }
    }
    if (writable && !write) write = ".operate";
    return { read, write: writable ? write : null, invoke, fabricScoped, sensitive, timed };
}

const lines = [];
const emit = line => lines.push(line);
emit("// Generated by Scripts/generate-clusters.mjs from matter.js's model of the Matter specification: do not edit.");
emit("// swiftlint:disable all");
emit("");

// Clusters.
const clusters = kinds("Cluster").filter(cluster => cluster.id !== undefined && cluster.id !== null).map(resolved);
emit("extension ClusterDefinition {");
emit("    /// Every standard cluster, by id.");
emit("    public static let standard: [ClusterID: ClusterDefinition] = [");
for (const cluster of clusters) emit(`        ${hex(cluster.id, 4)}: ${typeNameOf(cluster)}.definition,`);
emit("    ]");
emit("}");
emit("");

for (const cluster of clusters) {
    const typeName = typeNameOf(cluster);
    const attributes = childrenOf(cluster, "Attribute").filter(attribute => attribute.id !== undefined && attribute.id < 0xFFF0);
    const revisionAttribute = childrenOf(cluster, "Attribute").find(attribute => attribute.id === 0xFFFD);
    const revision = revisionAttribute?.default ?? 1;
    const featureMap = childrenOf(cluster, "Attribute").find(attribute => attribute.id === 0xFFFC);
    const features = featureMap ? childrenOf(featureMap, "Field") : [];
    const commands = childrenOf(cluster, "Command").filter(command => command.id !== undefined);
    const events = childrenOf(cluster, "Event").filter(event => event.id !== undefined);
    const enums = childrenOf(cluster, "Datatype").filter(datatype => /^enum/.test(datatype.type ?? ""));
    const structs = childrenOf(cluster, "Datatype").filter(datatype => datatype.type === "struct");

    emit(`/// ${cluster.name} (${hex(cluster.id, 4)}), revision ${revision}.`);
    emit(`public enum ${typeName} {`);
    emit(`    public static let id: ClusterID = ${hex(cluster.id, 4)}`);
    emit(`    public static let revision: UInt16 = ${revision}`);
    if (attributes.length) {
        emit("    public enum Attribute {");
        for (const attribute of attributes) emit(`        public static let ${camel(attribute.name)}: AttributeID = ${hex(attribute.id, 4)}`);
        emit("    }");
    }
    if (commands.length) {
        emit("    public enum Command {");
        for (const command of commands) emit(`        public static let ${camel(command.name)}: CommandID = ${hex(command.id, 2)}`);
        emit("    }");
    }
    if (events.length) {
        emit("    public enum Event {");
        for (const event of events) emit(`        public static let ${camel(event.name)}: EventID = ${hex(event.id, 2)}`);
        emit("    }");
    }
    if (features.length) {
        emit("    public struct Feature: OptionSet, Sendable {");
        emit("        public let rawValue: UInt32");
        emit("        public init(rawValue: UInt32) { self.rawValue = rawValue }");
        for (const feature of features) {
            if (typeof feature.constraint !== "string" && typeof feature.constraint !== "number") continue;
            const bit = Number(feature.constraint);
            if (Number.isNaN(bit)) continue;
            emit(`        public static let ${camel(feature.title ?? feature.name)} = Feature(rawValue: 1 << ${bit})`);
        }
        emit("    }");
    }
    for (const datatype of enums) {
        const values = childrenOf(datatype, "Field").filter(field => field.id !== undefined);
        if (!values.length) continue;
        emit(`    public enum ${datatype.name.replace(/[^A-Za-z0-9]/g, "")} {`);
        for (const field of values) emit(`        public static let ${camel(field.name)}: UInt64 = ${field.id}`);
        emit("    }");
    }

    for (const datatype of structs) {
        const fields = childrenOf(datatype, "Field").filter(field => field.id !== undefined);
        if (!fields.length) continue;
        emit(`    /// The field tags of ${datatype.name}.`);
        emit(`    public enum ${datatype.name.replace(/[^A-Za-z0-9]/g, "")} {`);
        for (const field of fields) emit(`        public static let ${camel(field.name)}: UInt8 = ${field.id}`);
        emit("    }");
    }
    emit("    public static let definition = ClusterDefinition(");
    emit(`        id: ${hex(cluster.id, 4)}, name: "${cluster.name}", revision: ${revision},`);
    emit("        attributes: [");
    for (const attribute of attributes) {
        const rights = access(attribute.access, { kind: "attribute", read: ".view" });
        const quality = (attribute.quality ?? "").split(/\s+/);
        const flags = [];
        if (attribute.type === "list") flags.push(".list");
        if (rights.fabricScoped) flags.push(".fabricScoped");
        if (rights.sensitive) flags.push(".fabricSensitive");
        if (rights.timed || quality.includes("T")) flags.push(".timedWrite");
        if (quality.includes("X")) flags.push(".nullable");
        if (quality.includes("F")) flags.push(".fixed");
        if (quality.includes("C")) flags.push(".changesOmitted");
        if (quality.includes("N")) flags.push(".nonVolatile");
        const write = rights.write ? `, write: ${rights.write}` : "";
        emit(`            AttributeDefinition(id: ${hex(attribute.id, 4)}, name: "${attribute.name}", type: "${attribute.type ?? ""}", read: ${rights.read}${write}, flags: [${flags.join(", ")}]),`);
    }
    emit("        ],");
    emit("        commands: [");
    for (const command of commands.filter(command => command.direction !== "response")) {
        const rights = access(command.access, { kind: "command", invoke: ".operate" });
        const response = command.response && command.response !== "status"
            ? commands.find(candidate => candidate.name === command.response && candidate.direction === "response")
            : undefined;
        emit(`            CommandDefinition(id: ${hex(command.id, 2)}, name: "${command.name}", invoke: ${rights.invoke}, timed: ${rights.timed}, fabricScoped: ${rights.fabricScoped}, response: ${response ? hex(response.id, 2) : "nil"}),`);
    }
    emit("        ],");
    emit("        events: [");
    for (const event of events) {
        const rights = access(event.access, { kind: "attribute", read: ".view" });
        emit(`            EventDefinition(id: ${hex(event.id, 2)}, name: "${event.name}", priority: .${(event.priority ?? "info").toLowerCase()}, read: ${rights.read}, fabricSensitive: ${rights.sensitive}),`);
    }
    emit("        ]");
    emit("    )");
    emit("}");
    emit("");
}

// Device types.
emit("/// Device types (Device Library), with their revisions and mandatory server clusters.");
emit("public enum DeviceTypes {");
for (const deviceType of kinds("DeviceType").filter(deviceType => deviceType.id !== undefined)) {
    const clusters = childrenOf(deviceType, "Requirement").filter(requirement => requirement.element === "serverCluster");
    const descriptor = clusters.find(requirement => requirement.id === 0x1d);
    const list = descriptor && childrenOf(descriptor, "Requirement").find(requirement => requirement.name === "DeviceTypeList");
    const revision = list?.default?.find?.(entry => entry.deviceType === deviceType.id)?.revision ?? 1;
    const mandatory = clusters.filter(requirement => requirement.conformance === "M" || requirement.conformance === undefined)
        .map(requirement => hex(requirement.id, 4));
    emit(`    public static let ${camel(deviceType.name)} = DeviceType(id: ${hex(deviceType.id, 4)}, revision: ${revision}, name: "${deviceType.name}", requiredServerClusters: [${mandatory.join(", ")}])`);
}
emit("}");

process.stdout.write(lines.join("\n") + "\n");
