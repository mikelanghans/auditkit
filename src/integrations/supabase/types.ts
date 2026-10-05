export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      app_owners: {
        Row: {
          added_at: string
          email: string
        }
        Insert: {
          added_at?: string
          email: string
        }
        Update: {
          added_at?: string
          email?: string
        }
        Relationships: []
      }
      architectural_findings: {
        Row: {
          affected_files: Json
          audit_id: string
          created_at: string
          explanation: string | null
          fix_steps: Json
          id: string
          include_in_report: boolean
          recommendation: string | null
          severity: string
          title: string
          updated_at: string
        }
        Insert: {
          affected_files?: Json
          audit_id: string
          created_at?: string
          explanation?: string | null
          fix_steps?: Json
          id?: string
          include_in_report?: boolean
          recommendation?: string | null
          severity?: string
          title: string
          updated_at?: string
        }
        Update: {
          affected_files?: Json
          audit_id?: string
          created_at?: string
          explanation?: string | null
          fix_steps?: Json
          id?: string
          include_in_report?: boolean
          recommendation?: string | null
          severity?: string
          title?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "architectural_findings_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_findings: {
        Row: {
          ai_assisted: boolean
          audit_id: string
          auto_scanned: boolean
          checklist_item_id: string
          claude_prompt: string | null
          created_at: string
          cursor_prompt: string | null
          evidence_text: string | null
          evidence_url: string | null
          explanation: string | null
          id: string
          lovable_prompt: string | null
          notes: string | null
          resolved_at: string | null
          resolved_via: string | null
          status: Database["public"]["Enums"]["finding_status"] | null
          updated_at: string
        }
        Insert: {
          ai_assisted?: boolean
          audit_id: string
          auto_scanned?: boolean
          checklist_item_id: string
          claude_prompt?: string | null
          created_at?: string
          cursor_prompt?: string | null
          evidence_text?: string | null
          evidence_url?: string | null
          explanation?: string | null
          id?: string
          lovable_prompt?: string | null
          notes?: string | null
          resolved_at?: string | null
          resolved_via?: string | null
          status?: Database["public"]["Enums"]["finding_status"] | null
          updated_at?: string
        }
        Update: {
          ai_assisted?: boolean
          audit_id?: string
          auto_scanned?: boolean
          checklist_item_id?: string
          claude_prompt?: string | null
          created_at?: string
          cursor_prompt?: string | null
          evidence_text?: string | null
          evidence_url?: string | null
          explanation?: string | null
          id?: string
          lovable_prompt?: string | null
          notes?: string | null
          resolved_at?: string | null
          resolved_via?: string | null
          status?: Database["public"]["Enums"]["finding_status"] | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "audit_findings_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "audit_findings_checklist_item_id_fkey"
            columns: ["checklist_item_id"]
            isOneToOne: false
            referencedRelation: "checklist_items"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_scope: {
        Row: {
          audit_id: string
          authorization_ref: string | null
          authorized_at: string | null
          authorized_by: string | null
          environment: string
          notes: string | null
          out_of_scope: string | null
          testing_window: string | null
          updated_at: string
          write_tests_allowed: boolean
        }
        Insert: {
          audit_id: string
          authorization_ref?: string | null
          authorized_at?: string | null
          authorized_by?: string | null
          environment?: string
          notes?: string | null
          out_of_scope?: string | null
          testing_window?: string | null
          updated_at?: string
          write_tests_allowed?: boolean
        }
        Update: {
          audit_id?: string
          authorization_ref?: string | null
          authorized_at?: string | null
          authorized_by?: string | null
          environment?: string
          notes?: string | null
          out_of_scope?: string | null
          testing_window?: string | null
          updated_at?: string
          write_tests_allowed?: boolean
        }
        Relationships: [
          {
            foreignKeyName: "audit_scope_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: true
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
        ]
      }
      audit_targets: {
        Row: {
          audit_id: string
          created_at: string
          id: string
          in_scope: boolean
          kind: string
          label: string | null
          meta: Json
          updated_at: string
          value: string
        }
        Insert: {
          audit_id: string
          created_at?: string
          id?: string
          in_scope?: boolean
          kind: string
          label?: string | null
          meta?: Json
          updated_at?: string
          value: string
        }
        Update: {
          audit_id?: string
          created_at?: string
          id?: string
          in_scope?: boolean
          kind?: string
          label?: string | null
          meta?: Json
          updated_at?: string
          value?: string
        }
        Relationships: [
          {
            foreignKeyName: "audit_targets_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
        ]
      }
      audits: {
        Row: {
          built_with: string | null
          client_id: string
          completed_at: string | null
          created_at: string
          created_by: string
          id: string
          started_at: string
          status: Database["public"]["Enums"]["audit_status"]
          summary: string | null
          title: string
          updated_at: string
          website_url: string | null
        }
        Insert: {
          built_with?: string | null
          client_id: string
          completed_at?: string | null
          created_at?: string
          created_by: string
          id?: string
          started_at?: string
          status?: Database["public"]["Enums"]["audit_status"]
          summary?: string | null
          title: string
          updated_at?: string
          website_url?: string | null
        }
        Update: {
          built_with?: string | null
          client_id?: string
          completed_at?: string | null
          created_at?: string
          created_by?: string
          id?: string
          started_at?: string
          status?: Database["public"]["Enums"]["audit_status"]
          summary?: string | null
          title?: string
          updated_at?: string
          website_url?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "audits_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      checklist_items: {
        Row: {
          category: string
          checklist_key: string | null
          created_at: string
          description: string | null
          id: string
          is_active: boolean
          severity: Database["public"]["Enums"]["severity"]
          sort_order: number
          title: string
          what_to_look_for: string | null
        }
        Insert: {
          category: string
          checklist_key?: string | null
          created_at?: string
          description?: string | null
          id?: string
          is_active?: boolean
          severity?: Database["public"]["Enums"]["severity"]
          sort_order?: number
          title: string
          what_to_look_for?: string | null
        }
        Update: {
          category?: string
          checklist_key?: string | null
          created_at?: string
          description?: string | null
          id?: string
          is_active?: boolean
          severity?: Database["public"]["Enums"]["severity"]
          sort_order?: number
          title?: string
          what_to_look_for?: string | null
        }
        Relationships: []
      }
      client_repos: {
        Row: {
          client_id: string
          created_at: string
          id: string
          label: string
          repo_url: string
          updated_at: string
          website_url: string | null
        }
        Insert: {
          client_id: string
          created_at?: string
          id?: string
          label: string
          repo_url: string
          updated_at?: string
          website_url?: string | null
        }
        Update: {
          client_id?: string
          created_at?: string
          id?: string
          label?: string
          repo_url?: string
          updated_at?: string
          website_url?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "client_repos_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      clients: {
        Row: {
          annual_revenue_range: string | null
          contact_email: string | null
          contact_name: string | null
          created_at: string
          created_by: string
          engagement_type: Database["public"]["Enums"]["engagement_type"]
          has_agentic_features: boolean
          id: string
          industry: string | null
          name: string
          notes: string | null
          updated_at: string
          user_count_range: string | null
          uses_ai_features: boolean
          websites: string[]
        }
        Insert: {
          annual_revenue_range?: string | null
          contact_email?: string | null
          contact_name?: string | null
          created_at?: string
          created_by: string
          engagement_type?: Database["public"]["Enums"]["engagement_type"]
          has_agentic_features?: boolean
          id?: string
          industry?: string | null
          name: string
          notes?: string | null
          updated_at?: string
          user_count_range?: string | null
          uses_ai_features?: boolean
          websites?: string[]
        }
        Update: {
          annual_revenue_range?: string | null
          contact_email?: string | null
          contact_name?: string | null
          created_at?: string
          created_by?: string
          engagement_type?: Database["public"]["Enums"]["engagement_type"]
          has_agentic_features?: boolean
          id?: string
          industry?: string | null
          name?: string
          notes?: string | null
          updated_at?: string
          user_count_range?: string | null
          uses_ai_features?: boolean
          websites?: string[]
        }
        Relationships: []
      }
      code_audit_findings: {
        Row: {
          audit_id: string
          blockers: Json | null
          checklist_item_id: string | null
          created_at: string
          description: string | null
          evidence: Json | null
          fingerprint: string
          id: string
          include_in_report: boolean
          raw: Json
          remediation: Json | null
          review_state: string
          reviewer_note: string | null
          root_cause: string | null
          run_id: string
          severity: string | null
          title: string
          trace: Json | null
          validation_plan: Json | null
          verdict: string
        }
        Insert: {
          audit_id: string
          blockers?: Json | null
          checklist_item_id?: string | null
          created_at?: string
          description?: string | null
          evidence?: Json | null
          fingerprint: string
          id?: string
          include_in_report?: boolean
          raw: Json
          remediation?: Json | null
          review_state?: string
          reviewer_note?: string | null
          root_cause?: string | null
          run_id: string
          severity?: string | null
          title: string
          trace?: Json | null
          validation_plan?: Json | null
          verdict: string
        }
        Update: {
          audit_id?: string
          blockers?: Json | null
          checklist_item_id?: string | null
          created_at?: string
          description?: string | null
          evidence?: Json | null
          fingerprint?: string
          id?: string
          include_in_report?: boolean
          raw?: Json
          remediation?: Json | null
          review_state?: string
          reviewer_note?: string | null
          root_cause?: string | null
          run_id?: string
          severity?: string | null
          title?: string
          trace?: Json | null
          validation_plan?: Json | null
          verdict?: string
        }
        Relationships: [
          {
            foreignKeyName: "code_audit_findings_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "code_audit_findings_checklist_item_id_fkey"
            columns: ["checklist_item_id"]
            isOneToOne: false
            referencedRelation: "checklist_items"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "code_audit_findings_run_id_fkey"
            columns: ["run_id"]
            isOneToOne: false
            referencedRelation: "code_audit_runs"
            referencedColumns: ["id"]
          },
        ]
      }
      code_audit_runs: {
        Row: {
          agents_used: number | null
          audit_id: string
          budget_agents: number
          confirmed_count: number
          coverage: Json | null
          created_at: string
          created_by: string
          error: string | null
          findings_detail_md: string | null
          finished_at: string | null
          git_ref: string | null
          id: string
          incomplete_reason: string | null
          needs_validation_count: number
          needs_validation_md: string | null
          profile: string
          progress: Json | null
          progress_at: string | null
          rejected_count: number
          repo_url: string
          report_md: string | null
          runner_machine_id: string | null
          source_commit: string | null
          started_at: string | null
          status: string
        }
        Insert: {
          agents_used?: number | null
          audit_id: string
          budget_agents: number
          confirmed_count?: number
          coverage?: Json | null
          created_at?: string
          created_by: string
          error?: string | null
          findings_detail_md?: string | null
          finished_at?: string | null
          git_ref?: string | null
          id?: string
          incomplete_reason?: string | null
          needs_validation_count?: number
          needs_validation_md?: string | null
          profile: string
          progress?: Json | null
          progress_at?: string | null
          rejected_count?: number
          repo_url: string
          report_md?: string | null
          runner_machine_id?: string | null
          source_commit?: string | null
          started_at?: string | null
          status?: string
        }
        Update: {
          agents_used?: number | null
          audit_id?: string
          budget_agents?: number
          confirmed_count?: number
          coverage?: Json | null
          created_at?: string
          created_by?: string
          error?: string | null
          findings_detail_md?: string | null
          finished_at?: string | null
          git_ref?: string | null
          id?: string
          incomplete_reason?: string | null
          needs_validation_count?: number
          needs_validation_md?: string | null
          profile?: string
          progress?: Json | null
          progress_at?: string | null
          rejected_count?: number
          repo_url?: string
          report_md?: string | null
          runner_machine_id?: string | null
          source_commit?: string | null
          started_at?: string | null
          status?: string
        }
        Relationships: [
          {
            foreignKeyName: "code_audit_runs_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
        ]
      }
      finding_audit_log: {
        Row: {
          after_status: string | null
          audit_id: string
          before_status: string | null
          created_at: string
          event_type: string
          evidence_text: string | null
          evidence_url: string | null
          finding_id: string
          id: string
          performed_by: string | null
          scan_result: Json | null
        }
        Insert: {
          after_status?: string | null
          audit_id: string
          before_status?: string | null
          created_at?: string
          event_type: string
          evidence_text?: string | null
          evidence_url?: string | null
          finding_id: string
          id?: string
          performed_by?: string | null
          scan_result?: Json | null
        }
        Update: {
          after_status?: string | null
          audit_id?: string
          before_status?: string | null
          created_at?: string
          event_type?: string
          evidence_text?: string | null
          evidence_url?: string | null
          finding_id?: string
          id?: string
          performed_by?: string | null
          scan_result?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "finding_audit_log_audit_id_fkey"
            columns: ["audit_id"]
            isOneToOne: false
            referencedRelation: "audits"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "finding_audit_log_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "audit_findings"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          created_at: string
          email: string | null
          full_name: string | null
          id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          email?: string | null
          full_name?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          email?: string | null
          full_name?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      public_checks: {
        Row: {
          created_at: string
          email: string | null
          email_captured_at: string | null
          error: string | null
          findings: Json | null
          hostname: string
          id: string
          ip_hash: string
          lead_status: string
          marketing_consent: boolean
          owner_notified_at: string | null
          report_sent_at: string | null
          status: string
          summary: Json | null
          url: string
        }
        Insert: {
          created_at?: string
          email?: string | null
          email_captured_at?: string | null
          error?: string | null
          findings?: Json | null
          hostname: string
          id?: string
          ip_hash: string
          lead_status?: string
          marketing_consent?: boolean
          owner_notified_at?: string | null
          report_sent_at?: string | null
          status?: string
          summary?: Json | null
          url: string
        }
        Update: {
          created_at?: string
          email?: string | null
          email_captured_at?: string | null
          error?: string | null
          findings?: Json | null
          hostname?: string
          id?: string
          ip_hash?: string
          lead_status?: string
          marketing_consent?: boolean
          owner_notified_at?: string | null
          report_sent_at?: string | null
          status?: string
          summary?: Json | null
          url?: string
        }
        Relationships: []
      }
      threat_feed_items: {
        Row: {
          advisory_url: string | null
          approved_checklist_item_id: string | null
          created_at: string
          external_id: string
          id: string
          is_relevant: boolean
          raw_summary: string | null
          raw_title: string
          reviewed_at: string | null
          reviewed_by: string | null
          source: string
          status: string
          suggested_category: string | null
          suggested_fix: string | null
          suggested_risk: string | null
          suggested_severity: Database["public"]["Enums"]["severity"] | null
          suggested_title: string | null
          updated_at: string
        }
        Insert: {
          advisory_url?: string | null
          approved_checklist_item_id?: string | null
          created_at?: string
          external_id: string
          id?: string
          is_relevant?: boolean
          raw_summary?: string | null
          raw_title: string
          reviewed_at?: string | null
          reviewed_by?: string | null
          source: string
          status?: string
          suggested_category?: string | null
          suggested_fix?: string | null
          suggested_risk?: string | null
          suggested_severity?: Database["public"]["Enums"]["severity"] | null
          suggested_title?: string | null
          updated_at?: string
        }
        Update: {
          advisory_url?: string | null
          approved_checklist_item_id?: string | null
          created_at?: string
          external_id?: string
          id?: string
          is_relevant?: boolean
          raw_summary?: string | null
          raw_title?: string
          reviewed_at?: string | null
          reviewed_by?: string | null
          source?: string
          status?: string
          suggested_category?: string | null
          suggested_fix?: string | null
          suggested_risk?: string | null
          suggested_severity?: Database["public"]["Enums"]["severity"] | null
          suggested_title?: string | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "threat_feed_items_approved_checklist_item_id_fkey"
            columns: ["approved_checklist_item_id"]
            isOneToOne: false
            referencedRelation: "checklist_items"
            referencedColumns: ["id"]
          },
        ]
      }
      usage_counters: {
        Row: {
          count: number
          day: string
          kind: string
          user_id: string
        }
        Insert: {
          count?: number
          day: string
          kind: string
          user_id: string
        }
        Update: {
          count?: number
          day?: string
          kind?: string
          user_id?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      am_i_app_owner: { Args: never; Returns: boolean }
      begin_public_check: {
        Args: { p_hostname: string; p_ip_hash: string; p_url: string }
        Returns: Json
      }
      consume_quota: {
        Args: { p_amount?: number; p_kind: string }
        Returns: Json
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      is_app_owner_session: { Args: never; Returns: boolean }
    }
    Enums: {
      app_role: "admin" | "auditor"
      audit_status: "draft" | "in_progress" | "completed"
      engagement_type: "prospect" | "one_time" | "retainer"
      finding_status: "pass" | "fail" | "na" | "resolved" | "inconclusive"
      severity: "critical" | "high" | "medium" | "low"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "auditor"],
      audit_status: ["draft", "in_progress", "completed"],
      engagement_type: ["prospect", "one_time", "retainer"],
      finding_status: ["pass", "fail", "na", "resolved", "inconclusive"],
      severity: ["critical", "high", "medium", "low"],
    },
  },
} as const
