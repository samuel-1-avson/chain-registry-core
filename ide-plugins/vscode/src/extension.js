const vscode = require('vscode');
const jsonc = require('jsonc-parser');
const WebSocket = require('ws');

const API_BASE = 'http://127.0.0.1:8080/v1/packages/';
const API_WS   = 'ws://127.0.0.1:8080/v1/ws';
const DIAGNOSTIC_SOURCE = 'Chain Registry';

let diagnosticCollection;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Chain Registry Security Extension Activated.');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('chainRegistry');
    context.subscriptions.push(diagnosticCollection);

    // Initial WebSocket setup for 0-day alerts
    setupWebSocket();

    // Command to manually trigger scan
    const scanCommand = vscode.commands.registerCommand('chainRegistry.scan', () => {
        if (vscode.window.activeTextEditor) {
            scanDocument(vscode.window.activeTextEditor.document);
        }
    });
    context.subscriptions.push(scanCommand);

    // Watch for active editor changes
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) scanDocument(editor.document);
        })
    );

    // Watch for document saves
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            scanDocument(document);
        })
    );

    // Initial scan
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}

async function scanDocument(document) {
    // Only target package.json
    if (!document.fileName.endsWith('package.json')) return;

    diagnosticCollection.delete(document.uri);
    const text = document.getText();
    const tree = jsonc.parseTree(text);
    if (!tree) return;

    const diagnostics = [];

    // Find "dependencies" and "devDependencies" in root
    const depsNode = jsonc.findNodeAtLocation(tree, ['dependencies']);
    const devDepsNode = jsonc.findNodeAtLocation(tree, ['devDependencies']);

    const promises = [];

    if (depsNode && depsNode.children) {
        for (const child of depsNode.children) promises.push(checkDependency(document, child, diagnostics));
    }
    if (devDepsNode && devDepsNode.children) {
        for (const child of devDepsNode.children) promises.push(checkDependency(document, child, diagnostics));
    }

    await Promise.all(promises);
    diagnosticCollection.set(document.uri, diagnostics);
}

async function checkDependency(document, propertyNode, diagnosticsOut) {
    if (!propertyNode || propertyNode.children.length !== 2) return;
    
    // index 0 is the key (package name), index 1 is the value (version)
    const pkgNameNode = propertyNode.children[0];
    const pkgName = pkgNameNode.value;

    try {
        const url = API_BASE + encodeURIComponent(`${pkgName}`);
        const res = await fetch(url, { headers: { 'Accept': 'application/json' }});
        
        if (res.status === 404) {
            // Unregistered on the decentralized chain
            addDiagnostic(
                document, pkgNameNode, diagnosticsOut, 
                `[Unverified] ${pkgName} is not registered on the Chain Registry. Use with caution.`,
                vscode.DiagnosticSeverity.Hint
            );
            return;
        }

        const data = await res.json();
        
        if (data.status === 'revoked') {
            // Found Malicious Intent / Vulnerability / Slashed Node
            addDiagnostic(
                document, pkgNameNode, diagnosticsOut, 
                `[🚨 MALICIOUS REVOKED] ${pkgName} was slashed by consensus.\nReason: ${data.revocation_reason}`,
                vscode.DiagnosticSeverity.Error
            );
        } else if (data.status === 'pending') {
            addDiagnostic(
                document, pkgNameNode, diagnosticsOut, 
                `[Pending Audit] ${pkgName} is currently undergoing AI consensus scanning. Installation may be blocklisted soon.`,
                vscode.DiagnosticSeverity.Warning
            );
        } else if (data.status === 'verified') {
            // Nothing. Standard clean check.
        }
    } catch (err) {
        console.error('Failed to contact Chain Registry node:', err);
    }
}

function addDiagnostic(document, node, diagnosticsArray, message, severity) {
    const startPos = document.positionAt(node.offset);
    const endPos = document.positionAt(node.offset + node.length);
    const range = new vscode.Range(startPos, endPos);
    
    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnosticsArray.push(diagnostic);
}

function setupWebSocket() {
    const ws = new WebSocket(API_WS);

    ws.on('message', (data) => {
        try {
            const registryEvent = JSON.parse(data.toString());
            if (registryEvent.kind === 'package_revoked' || registryEvent.kind === 'PackageRevoked') {
                const canonical = registryEvent.payload.canonical;
                console.log(`[0-Day Alert] Package revoked: ${canonical}`);
                
                // If the active document is a package.json, re-scan it immediately
                if (vscode.window.activeTextEditor && 
                    vscode.window.activeTextEditor.document.fileName.endsWith('package.json')) {
                    scanDocument(vscode.window.activeTextEditor.document);
                }
            }
        } catch (e) {
            console.error('Failed to parse WebSocket message:', e);
        }
    });

    ws.on('error', (error) => {
        // Silently fail if node is not running
    });

    ws.on('close', () => {
        setTimeout(setupWebSocket, 5000);
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
