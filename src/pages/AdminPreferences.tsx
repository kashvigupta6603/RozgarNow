import { useEffect, useState } from "react";
import Navigation from "@/components/Navigation";
import Footer from "@/components/Footer";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";


interface AdminPreference {
  id: number;
  qualification: string | null;
  location: string | null;
  experience: string | null;
  govt: string | null;
  category: string | null;
  keywords: string | null;
  user?: {
    id: number;
    name: string | null;
    email: string;
  };
}

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:4000";
  
const AdminPreferences = () => {
  const [prefs, setPrefs] = useState<AdminPreference[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchPreferences = async () => {
    try {
      setLoading(true);
      setError("");

      const token = localStorage.getItem("token");

      const res = await fetch(`${API_BASE_URL}/api/admin/preferences`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!res.ok) {
        throw new Error("Failed to load preferences");
      }

      const data = await res.json();
      console.log("ADMIN PREFS RESPONSE =>", data); // debug

      // 👇 IMPORTANT: backend key is `prefs`
      setPrefs(data.prefs || []);
    } catch (err: any) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPreferences();
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <h1 className="text-3xl font-bold mb-6">User Preferences</h1>

        {loading && <p>Loading preferences...</p>}
        {error && !loading && (
          <p className="text-red-500 mb-4">{error}</p>
        )}

        {!loading && !error && (
          <Card>
            <CardHeader>
              <CardTitle>Saved preference profiles ({prefs.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {prefs.length === 0 ? (
                <p className="text-muted-foreground">
                  No preferences found.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Qualification</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Govt Type</TableHead>
                      <TableHead>Categories</TableHead>
                      <TableHead>Keywords</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {prefs.map((pref) => (
                      <TableRow key={pref.id}>
                        <TableCell>{pref.user?.name || "—"}</TableCell>
                        <TableCell>{pref.user?.email}</TableCell>
                        <TableCell>{pref.qualification || "—"}</TableCell>
                        <TableCell>{pref.location || "—"}</TableCell>
                        <TableCell>{pref.govt || "—"}</TableCell>
                        <TableCell>{pref.category || "—"}</TableCell>
                        <TableCell>{pref.keywords || "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      <Footer />
    </div>
  );
};

export default AdminPreferences;
