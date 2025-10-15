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
    PostgrestVersion: "13.0.4"
  }
  public: {
    Tables: {
      cve: {
        Row: {
          cve_id: string
          cvss_score: number | null
          description: string
          title: string
        }
        Insert: {
          cve_id: string
          cvss_score?: number | null
          description: string
          title: string
        }
        Update: {
          cve_id?: string
          cvss_score?: number | null
          description?: string
          title?: string
        }
        Relationships: []
      }
      findings: {
        Row: {
          cve_id: string | null
          finding_id: string
          host: string | null
          port: number
          scan_id: string
          service_name: string
          service_version: string | null
          state: string | null
        }
        Insert: {
          cve_id?: string | null
          finding_id?: string
          host?: string | null
          port: number
          scan_id: string
          service_name: string
          service_version?: string | null
          state?: string | null
        }
        Update: {
          cve_id?: string | null
          finding_id?: string
          host?: string | null
          port?: number
          scan_id?: string
          service_name?: string
          service_version?: string | null
          state?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "findings_cve_id_fkey"
            columns: ["cve_id"]
            isOneToOne: false
            referencedRelation: "cve"
            referencedColumns: ["cve_id"]
          },
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["scan_id"]
          },
        ]
      }
      reports: {
        Row: {
          created_at: string
          fix_recommendations: string | null
          pdf_url: string | null
          report_id: string
          scan_id: string
          summary: string | null
        }
        Insert: {
          created_at?: string
          fix_recommendations?: string | null
          pdf_url?: string | null
          report_id?: string
          scan_id: string
          summary?: string | null
        }
        Update: {
          created_at?: string
          fix_recommendations?: string | null
          pdf_url?: string | null
          report_id?: string
          scan_id?: string
          summary?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "reports_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: true
            referencedRelation: "scans"
            referencedColumns: ["scan_id"]
          },
        ]
      }
      scans: {
        Row: {
          end_time: string | null
          host_info: Json | null
          nmap_cmd: string | null
          nmap_output: string | null
          profile: string | null
          scan_depth: string | null
          scan_id: string
          scan_source: string | null
          start_time: string | null
          status: string | null
          target: string
          use_arp_discovery: boolean | null
          user_id: string
        }
        Insert: {
          end_time?: string | null
          host_info?: Json | null
          nmap_cmd?: string | null
          nmap_output?: string | null
          profile?: string | null
          scan_depth?: string | null
          scan_id?: string
          scan_source?: string | null
          start_time?: string | null
          status?: string | null
          target: string
          use_arp_discovery?: boolean | null
          user_id: string
        }
        Update: {
          end_time?: string | null
          host_info?: Json | null
          nmap_cmd?: string | null
          nmap_output?: string | null
          profile?: string | null
          scan_depth?: string | null
          scan_id?: string
          scan_source?: string | null
          start_time?: string | null
          status?: string | null
          target?: string
          use_arp_discovery?: boolean | null
          user_id?: string
        }
        Relationships: []
      }
      users: {
        Row: {
          created_at: string
          email: string
          name: string
          password_hash: string
          user_id: string
        }
        Insert: {
          created_at?: string
          email: string
          name: string
          password_hash: string
          user_id: string
        }
        Update: {
          created_at?: string
          email?: string
          name?: string
          password_hash?: string
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
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
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
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
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
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
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
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
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
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
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
