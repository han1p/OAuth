import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { AuthGuard } from './auth.guard';  // The route guard we created

const routes: Routes = [
  { path: '', component: HomeComponent }, // Home route (default)
  { path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] },  // Protect dashboard route
  { path: '**', redirectTo: '' }  // Redirect any unknown route to Home
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }

