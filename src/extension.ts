import * as vscode from 'vscode';
import { scanShellInjection, scanNetHttpInLoop, scanGemfileGroups } from './scanners';
import { recordHit } from './reviewPrompt';

let diagnostics: vscode.DiagnosticCollection;

function basename(uri: vscode.Uri): string {
  const path = uri.path;
  return path.slice(path.lastIndexOf('/') + 1);
}

function toDiagnostics(
  context: vscode.ExtensionContext,
  document: vscode.TextDocument,
  hits: { line: number; rule: string; message: string }[],
): vscode.Diagnostic[] {
  return hits.map((hit) => {
    // Line-only precision (no column tracking in these ports, matching
    // the originals' own hit shape for nethttp/gemfile) -- underline
    // the whole line rather than guessing a column.
    const range = new vscode.Range(hit.line - 1, 0, hit.line - 1, Number.MAX_SAFE_INTEGER);
    const diagnostic = new vscode.Diagnostic(range, hit.message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'Ruby Companion';
    diagnostic.code = hit.rule;
    recordHit(context, `${document.uri.toString()}:${hit.rule}:${hit.line - 1}`);
    return diagnostic;
  });
}

function refresh(context: vscode.ExtensionContext, document: vscode.TextDocument): void {
  const name = basename(document.uri);
  const isRubySource = document.languageId === 'ruby' || name.endsWith('.rb');
  const isGemfile = name === 'Gemfile' || name.endsWith('.gemfile');

  if (!isRubySource && !isGemfile) return;

  const text = document.getText();
  const hits = isGemfile
    ? scanGemfileGroups(text)
    : [...scanShellInjection(text), ...scanNetHttpInLoop(text)];

  diagnostics.set(document.uri, toDiagnostics(context, document, hits));
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('rubyCompanion');
  context.subscriptions.push(diagnostics);

  vscode.workspace.textDocuments.forEach((doc) => refresh(context, doc));

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => refresh(context, doc)),
    vscode.workspace.onDidChangeTextDocument((event) => refresh(context, event.document)),
    vscode.workspace.onDidCloseTextDocument((document) => diagnostics.delete(document.uri)),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}
