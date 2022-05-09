using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor;

namespace LamNT.MiTransport
{
    [CustomEditor(typeof(MiTransport))]
    public class MiTransportEditor : Editor
    {
        SerializedProperty logError;
        SerializedProperty serverKey;
        SerializedProperty clientKey;
        SerializedProperty innerTransport;

        private void OnEnable()
        {
            logError = serializedObject.FindProperty("_logError");
            innerTransport = serializedObject.FindProperty("_innerTransport");
            serverKey = serializedObject.FindProperty("serverKey");
            clientKey = serializedObject.FindProperty("clientKey");
        }

        public override void OnInspectorGUI()
        {
            serializedObject.Update();
            EditorGUILayout.PropertyField(logError);
            EditorGUILayout.PropertyField(innerTransport);
            EditorGUILayout.PropertyField(serverKey);
            EditorGUILayout.PropertyField(clientKey);

            if (GUILayout.Button("Generate keypair"))
            {
                ((MiTransport)serializedObject.targetObject).GenerateKeyPair();
            }

            serializedObject.ApplyModifiedProperties();
        }
    }
}
